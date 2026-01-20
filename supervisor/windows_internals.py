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
        user_selection = "User files selection"
        rank = 'Rank relevancy'

    def __init__(self):
        super().__init__(llm=AgentModels.platform_internals_model.model)
        self.limit = 3

    def _build(self):
        if self._graph:
            return

        builder = StateGraph(WindowsInternalsContext)

        builder.add_node(self.NODES.collect, self.collect)
        builder.add_node(self.NODES.user_selection, self.user_selection)
        builder.add_node(self.NODES.rank, self.rank)

        builder.set_entry_point(self.NODES.collect)
        builder.add_edge(self.NODES.collect, self.NODES.user_selection)
        builder.add_edge(self.NODES.user_selection, self.NODES.rank)

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

    async def user_selection(self, context: WindowsInternalsContext):
        context.state_info.node.append(self.NODES.user_selection)
        
        user_docs = list(context.user_docs) if context.user_docs else []
        
        console.info(f'[*] Query additional files? ({len(context.docs)} found, {len(user_docs)} user-selected)')
        
        while True:
            print("\nOptions: semantic | filename | done")
            user_input = input("Select: ").strip().lower()
            
            if user_input == "done":
                break
            
            # Get search results
            search_results = []
            if user_input == "semantic":
                query = input("Query: ").strip()
                if query:
                    search_results = await VectorStore.file_info.asimilarity_search_with_score(query, k=10)
            
            elif user_input == "filename":
                pattern = input("Pattern: ").strip()
                if pattern:
                    try:
                        results = VectorStore.file_info.get(where={"name": {"$eq": pattern}}, limit=10)
                        if results and results.get('documents'):
                            search_results = [
                                (Document(page_content=results['documents'][i], 
                                         metadata=results['metadatas'][i]), 0.5)
                                for i in range(len(results['documents']))
                            ]
                    except Exception as e:
                        logger.error(f"Filename search error: {e}")
                        continue
            else:
                continue
            
            if not search_results:
                print("No results found.")
                continue
            
            # Display and select
            for idx, (doc, score) in enumerate(search_results):
                name = doc.metadata.get('name', 'Unknown')
                print(f"{idx + 1}. {name} (score: {score:.3f})")
            
            selection = input("Select (e.g., 1,3,5 or 'all'): ").strip()
            if not selection:
                continue
            
            indices = (list(range(len(search_results))) if selection == 'all' 
                      else [int(i.strip()) - 1 for i in selection.split(',') 
                            if i.strip().isdigit() and 0 <= int(i.strip()) - 1 < len(search_results)])
            
            for idx in indices:
                doc, score = search_results[idx]
                if not any(d.metadata.get('name') == doc.metadata.get('name') for d, _ in user_docs):
                    user_docs.append((doc, score))
                    print(f"+ {doc.metadata.get('name', 'Unknown')}")
        
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
        
        
        console.info(f'[*] Final ranking: {len(ranked_docs)} documents ({len(user_ranked_docs)} user-selected)')

        return {'candidates': Candidates(query=context.query,
                                         results=sorted(ranked_docs + user_ranked_docs, key=lambda t: t[2],
                                                        reverse=True))}

