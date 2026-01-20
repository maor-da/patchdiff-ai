import asyncio
import json

from langchain_core.documents import Document
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.graph import StateGraph
from pydantic import BaseModel, Field

from agent import Agent
from agent_tools.vector_store import VectorStore
from common import AgentModels, StateInfo, CveDetails, Candidates, LLM, logger, console
from defaultdataclass import defaultdataclass
from langgraph.constants import END


@defaultdataclass
class WindowsInternalsContext:
    state_info: StateInfo
    cve_details: CveDetails
    query: str
    docs: list[tuple[Document, float]]
    user_docs: list[tuple[Document, float]]


@defaultdataclass
class WindowsInternalsOutput:
    candidates: Candidates


@defaultdataclass
class PromptTemplate:
    collect: ChatPromptTemplate
    rank: ChatPromptTemplate


class FileScore(BaseModel):
    file: str = Field(..., description="Filename including extension")
    score: float = Field(..., description="Relevance score from 0.0 to 10.0, higher is more relevant")
    # reason: str = Field(..., description="One sentence about the reason for this score")


class FileScoreList(BaseModel):
    files: list[FileScore]


class Query(BaseModel):
    query: str = Field(..., description="Query to use for similarity search in the vectorstore")


class WindowsInternals(Agent):
    '''
    This agent has access to Windows executable files information
    through the file info vectorstore.
    It can find executables that could be related to a description
    of flow, vulnerability, and other scenarios.
    '''

    prompt_template: PromptTemplate = PromptTemplate(
        collect=ChatPromptTemplate([
            SystemMessage(
                # ---- WHAT TO DO -------------------------------------------------
                "You receive a JSON object that pinpoints WHERE the bug was fixed "
                "(driver / service / DLL / EXE name appears in the title or description).\n"
                "Write ONE paragraph, <= 80 tokens, plain ASCII.\n"
                "That paragraph must sound like a terse engineer-authored note for the "
                "*ordinary* behaviour of the exact file that got patched.\n"
                # ---- HOW TO DO IT ----------------------------------------------
                "Mandatory content:\n"
                "1) The executable’s primary job (e.g. ‘copies log sectors into caller buffer’).\n"
                "2) Key internal logic tied to that job (loops, size checks, pointer math, "
                "   registry access, IRP handling, etc.).\n"
                "3) Main OS components or APIs it talks to (Mm, Io, ALPC, SrvNet…).\n"
                "4) Its purpose to the wider system (transaction logging, credential caching, …).\n"
                # ---- HARD BANS ---------------------------------------------------
                "Never say: CVE, CVSS, CWE, ‘bug’, ‘vulnerability’, patch status, risk, exploit.\n"
                "No headings, lists, or newlines. No code blocks. No fluffy adjectives.\n"
                # ---- STYLE -------------------------------------------------------
                "Use present tense. Technical verbs only. Keep it punchy and factual."
            ),
            MessagesPlaceholder("json_metadata")
        ]),
        rank=ChatPromptTemplate.from_template(
            """
                You are an expert in Windows OS and at evaluating document relevance.
    
                ORIGINAL QUERY: {query}
                ORIGINAL JSON: {metadata}
    
                Below are documents retrieved from a vector store. Your task is to rerank them based on their relevance 
                to the original query and JSON data, assigning a score from 0.00 (completely irrelevant) to 10.00 (perfectly relevant).
    
                DOCUMENTS:
                {files}
    
                Analyze each document carefully and determine how well it addresses the information needs implied by the query and JSON.
                """
        ))

    @defaultdataclass(frozen=True)
    class NODES:
        collect = "Collect relevant files"
        query_more_files = "Query more files (Human-in-the-Loop)"
        rank = 'Rank relevancy'

    def __init__(self):
        super().__init__(llm=AgentModels.platform_internals_model.model)
        self.limit = 3

    def _build(self):
        if self._graph:
            return

        builder = StateGraph(WindowsInternalsContext)

        builder.add_node(self.NODES.collect, self.collect)
        builder.add_node(self.NODES.query_more_files, self.query_more_files)
        builder.add_node(self.NODES.rank, self.rank)

        builder.set_entry_point(self.NODES.collect)
        builder.add_edge(self.NODES.collect, self.NODES.query_more_files)
        builder.add_edge(self.NODES.query_more_files, self.NODES.rank)

        builder.add_conditional_edges(self.NODES.rank, self.refinement,
                                      [
                                          self.NODES.rank,
                                          END
                                      ])

        builder.set_finish_point(self.NODES.rank)

        self._graph = builder.compile()

    def refinement(self, context: WindowsInternalsOutput):

        if 'ok':
            return END

        if 'not ok':
            if self.limit:
                self.limit -= 1
                return self.NODES.rank

        return END

    async def collect(self, context: WindowsInternalsContext):
        context.state_info.node.append(self.NODES.collect)
        console.info(f'[*] Searching for potential candidates')
        query_chain = self.prompt_template.collect | self.get_llm().with_structured_output(Query)
        metadata = json.dumps({k: v for k, v in context.cve_details.msrc_report.to_dict().items() if k != 'products'})

        result: Query = await query_chain.ainvoke(
            {'json_metadata': [HumanMessage(metadata)]})

        docs = await VectorStore.file_info.asimilarity_search_with_score(result.query, k=10)  # TODO: add config
        logger.info(f'Found {len(docs)} docs for query "{result.query}"')

        if len(docs):
            console.info(f'[+] Found {len(docs)} potential candidates for {context.cve_details.cve} (limit: 10)')
        else:
            console.info(f'[-] Failed to find candidates for {context.cve_details}')

        return {'docs': docs, 'query': result.query}

    async def query_more_files(self, context: WindowsInternalsContext):
        context.state_info.node.append(self.NODES.query_more_files)
        
        # Initialize user_docs if not already set
        if not context.user_docs:
            user_docs = []
        else:
            user_docs = list(context.user_docs)
        
        console.info(f'[*] Human-in-the-Loop: Query for additional files')
        console.info(f'[*] Current results: {len(context.docs)} documents from initial search')
        console.info(f'[*] User-selected: {len(user_docs)} documents')
        
        while True:
            print("\n" + "="*60)
            print("Query More Files - Options:")
            print("  semantic  - Perform semantic search with custom query")
            print("  filename  - Search by filename/metadata pattern")
            print("  show      - Show current initial search results")
            print("  show-user - Show user-selected documents")
            print("  done      - Proceed to ranking")
            print("="*60)
            
            user_input = input("\nSelect option: ").strip().lower()
            
            if not user_input:
                continue
            
            if user_input == "done":
                console.info(f'[+] Proceeding with {len(user_docs)} user-selected documents')
                break
            
            elif user_input == "show":
                print("\nInitial Search Results:")
                print("-" * 60)
                for idx, (doc, score) in enumerate(context.docs):
                    name = doc.metadata.get('name', 'Unknown')
                    preview = doc.page_content[:100].replace('\n', ' ')
                    print(f"{idx + 1}. {name} (score: {score:.3f})")
                    print(f"   Preview: {preview}...")
                continue
            
            elif user_input == "show-user":
                if not user_docs:
                    print("\nNo user-selected documents yet.")
                else:
                    print("\nUser-Selected Documents:")
                    print("-" * 60)
                    for idx, (doc, score) in enumerate(user_docs):
                        name = doc.metadata.get('name', 'Unknown')
                        preview = doc.page_content[:100].replace('\n', ' ')
                        print(f"{idx + 1}. {name} (original score: {score:.3f})")
                        print(f"   Preview: {preview}...")
                continue
            
            elif user_input == "semantic":
                query = input("Enter semantic search query: ").strip()
                if not query:
                    console.info("[-] Empty query, skipping")
                    continue
                
                console.info(f'[*] Searching for: "{query}"')
                search_results = await VectorStore.file_info.asimilarity_search_with_score(query, k=10)
                
                if not search_results:
                    console.info(f'[-] No results found for query: "{query}"')
                    continue
                
                print(f"\nFound {len(search_results)} results:")
                print("-" * 60)
                for idx, (doc, score) in enumerate(search_results):
                    name = doc.metadata.get('name', 'Unknown')
                    preview = doc.page_content[:100].replace('\n', ' ')
                    print(f"{idx + 1}. {name} (score: {score:.3f})")
                    print(f"   Preview: {preview}...")
                
                selection = input("\nSelect documents by index (comma-separated, e.g., 1,3,5) or 'all': ").strip()
                
                if not selection:
                    continue
                
                if selection.lower() == 'all':
                    indices = list(range(len(search_results)))
                else:
                    try:
                        indices = [int(i.strip()) - 1 for i in selection.split(',')]
                        indices = [i for i in indices if 0 <= i < len(search_results)]
                    except ValueError:
                        console.info("[-] Invalid selection format")
                        continue
                
                for idx in indices:
                    doc, score = search_results[idx]
                    # Check if already selected
                    already_exists = any(
                        d.metadata.get('name') == doc.metadata.get('name') 
                        for d, _ in user_docs
                    )
                    if not already_exists:
                        user_docs.append((doc, score))
                        console.info(f'[+] Added: {doc.metadata.get("name", "Unknown")}')
                    else:
                        console.info(f'[*] Already selected: {doc.metadata.get("name", "Unknown")}')
            
            elif user_input == "filename":
                pattern = input("Enter filename pattern to search: ").strip()
                if not pattern:
                    console.info("[-] Empty pattern, skipping")
                    continue
                
                console.info(f'[*] Searching for files matching: "{pattern}"')
                
                try:
                    # Search using metadata filtering with contains
                    search_results = VectorStore.file_info.get(
                        where={"name": {"$contains": pattern}},
                        limit=10
                    )
                    
                    if not search_results or 'documents' not in search_results or not search_results['documents']:
                        console.info(f'[-] No files found matching pattern: "{pattern}"')
                        continue
                    
                    # Convert to format similar to similarity search
                    docs_with_scores = []
                    for i, doc_content in enumerate(search_results['documents']):
                        metadata = search_results['metadatas'][i] if 'metadatas' in search_results else {}
                        doc = Document(page_content=doc_content, metadata=metadata)
                        # Use a neutral score for filename-based search
                        docs_with_scores.append((doc, 0.5))
                    
                    print(f"\nFound {len(docs_with_scores)} results:")
                    print("-" * 60)
                    for idx, (doc, score) in enumerate(docs_with_scores):
                        name = doc.metadata.get('name', 'Unknown')
                        preview = doc.page_content[:100].replace('\n', ' ')
                        print(f"{idx + 1}. {name}")
                        print(f"   Preview: {preview}...")
                    
                    selection = input("\nSelect documents by index (comma-separated, e.g., 1,3,5) or 'all': ").strip()
                    
                    if not selection:
                        continue
                    
                    if selection.lower() == 'all':
                        indices = list(range(len(docs_with_scores)))
                    else:
                        try:
                            indices = [int(i.strip()) - 1 for i in selection.split(',')]
                            indices = [i for i in indices if 0 <= i < len(docs_with_scores)]
                        except ValueError:
                            console.info("[-] Invalid selection format")
                            continue
                    
                    for idx in indices:
                        doc, score = docs_with_scores[idx]
                        # Check if already selected
                        already_exists = any(
                            d.metadata.get('name') == doc.metadata.get('name') 
                            for d, _ in user_docs
                        )
                        if not already_exists:
                            user_docs.append((doc, score))
                            console.info(f'[+] Added: {doc.metadata.get("name", "Unknown")}')
                        else:
                            console.info(f'[*] Already selected: {doc.metadata.get("name", "Unknown")}')
                
                except Exception as e:
                    logger.error(f"Error during filename search: {e}")
                    console.info(f'[-] Error during search: {str(e)}')
                    continue
            
            else:
                console.info(f'[-] Unknown option: {user_input}')
                continue
        
        return {'user_docs': user_docs}

    async def rank(self, context: WindowsInternalsContext):
        context.state_info.node.append(self.NODES.rank)

        chain = self.prompt_template.rank | AgentModels.default_model.model.with_structured_output(FileScoreList)

        files = '\n\n'.join(f"name: {doc.metadata.get('name', '')}\n{doc.page_content}" for doc, _ in context.docs)
        metadata = json.dumps({k: v for k, v in context.cve_details.msrc_report.to_dict().items() if k != 'products'})

        console.info(f'[*] Ranking {context.cve_details.cve} candidates')

        result: FileScoreList = await chain.ainvoke({
            'query': context.query,
            'metadata': metadata,
            'files': files
        })

        score_map: dict[str, float] = {fs.file: fs.score for fs in result.files}
        ranked_docs = [(doc, score, score_map.get(doc.metadata.get("name"), 0.0)) for doc, score in context.docs]

        # Add user-selected docs with score 10.0
        user_ranked_docs = [(doc, score, 10.0) for doc, score in context.user_docs]
        
        # Merge and deduplicate based on filename
        # User docs take precedence (score 10.0)
        seen_names = set()
        all_ranked_docs = []
        
        # Add user docs first (they have priority with score 10.0)
        for doc, score, rank_score in user_ranked_docs:
            name = doc.metadata.get("name", "")
            if name and name not in seen_names:
                seen_names.add(name)
                all_ranked_docs.append((doc, score, rank_score))
        
        # Add initial docs, skipping duplicates
        for doc, score, rank_score in ranked_docs:
            name = doc.metadata.get("name", "")
            if name and name not in seen_names:
                seen_names.add(name)
                all_ranked_docs.append((doc, score, rank_score))
            elif not name:
                # Include docs without names (though this shouldn't happen)
                all_ranked_docs.append((doc, score, rank_score))
        
        console.info(f'[*] Final ranking: {len(all_ranked_docs)} documents ({len(user_ranked_docs)} user-selected)')

        return {'candidates': Candidates(query=context.query,
                                         results=sorted(all_ranked_docs, key=lambda t: t[2],
                                                        reverse=True))}

