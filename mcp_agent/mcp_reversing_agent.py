import difflib
import json
import operator
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph
from langgraph.prebuilt import create_react_agent

from agent import Agent
from agent_tools.ida_mcp_client import build_mcp_tools
from agent_tools.ida_mcp_launcher import IdaMcpLauncher
from common import (
    AgentModels,
    Artifact,
    CveDetails,
    StateInfo,
    Timer,
    console,
    logger,
)
from defaultdataclass import defaultdataclass, field
from vr_agent.vulnerability_researcher_agent import (
    DecompiledFunction,
    DecompiledFunctionMetadata,
    discover_parents,
)


MAX_WORKLIST = 40
MAX_FINDINGS = 15
RECURSION_LIMIT = 60


SYSTEM_PROMPT = """\
You are a binary-diff investigator with two headless idalib MCP servers.

Tool naming: the MCP client prefixes every tool with the server key so you
choose which binary a call targets:
  * primary_*   - the PATCHED binary ({primary_name})
  * secondary_* - the PREVIOUS binary ({secondary_name})

Available per-binary operations (use the matching prefix):
  decompile, disasm, lookup_funcs, get_bytes, get_int, get_string,
  xrefs_to, callees, find_regex, find_bytes, idalib_current

You are given a worklist of up to {max_worklist} BinDiff-changed function
pairs, sorted by suspicion (lowest similarity first, then highest confidence).
For each pair worth investigating, decompile it on both sides, judge whether
the change plausibly relates to the CVE below, and when it does call
`record_finding(...)` with the decompiler output verbatim so the downstream
vulnerability researcher can reason on it.

Budget:
  * Inspect no more than {max_worklist} pairs.
  * Record no more than {max_findings} findings.
  * Favour informative findings over exhaustive ones - stop as soon as the
    remaining pairs look cosmetic.

CVE metadata:
  id:          {cve}
  title:       {title}
  description: {description}

Worklist (primary_addr / secondary_addr / primary_name / similarity / confidence):
{worklist}
"""


@defaultdataclass
class McpResult:
    artifact: Artifact
    decompiled: list[DecompiledFunction] = field(default_factory=list)


@defaultdataclass
class McpReversingContext:
    state_info: StateInfo
    artifact: Artifact
    cve_details: CveDetails


@defaultdataclass
class McpReversingOutput:
    mcp_results: Annotated[list[McpResult], operator.add] = field(
        default_factory=list
    )


class McpReversing(Agent):
    """On-demand reverse-engineering driven by two idalib-mcp servers.

    A single ReAct node launches ``idalib-mcp`` for the patched and previous
    binaries, hands the model a worklist of BinDiff-changed functions, and
    harvests findings via a synthetic ``record_finding`` tool. The resulting
    ``list[DecompiledFunction]`` replaces the former ``__funcs__/*.c`` batch
    pipeline.
    """

    @dataclass(frozen=True)
    class NODES:
        investigate = "Investigate via idalib-mcp"

    def __init__(self):
        super().__init__()

    def _build(self):
        if self._graph:
            return

        builder = StateGraph(
            state_schema=McpReversingContext, output=McpReversingOutput
        )
        builder.add_node(self.NODES.investigate, self.investigate)
        builder.set_entry_point(self.NODES.investigate)
        builder.set_finish_point(self.NODES.investigate)

        self._graph = builder.compile()

    @staticmethod
    def _format_worklist(artifact: Artifact) -> str:
        lines = []
        for func in artifact.changed[:MAX_WORKLIST]:
            lines.append(
                f"  - 0x{func.address1:X} / 0x{func.address2:X} / "
                f"{func.name1} / sim={func.similarity:.3f} / "
                f"conf={func.confidence:.3f}"
            )
        return "\n".join(lines) or "  (empty)"

    async def investigate(self, context: McpReversingContext, config=None):
        context.state_info.node.append(self.NODES.investigate)

        artifact = context.artifact
        primary_i64 = Path(artifact.primary_file.path).with_suffix(".i64")
        secondary_i64 = Path(artifact.secondary_file.path).with_suffix(".i64")

        if not primary_i64.exists() or not secondary_i64.exists():
            logger.error(
                f"Missing idalib IDBs for {artifact.primary_file.name}: "
                f"primary={primary_i64.exists()} secondary={secondary_i64.exists()}"
            )
            return {"mcp_results": [McpResult(artifact=artifact, decompiled=[])]}

        findings: list[DecompiledFunction] = []

        @tool
        def record_finding(
            primary_address: str,
            secondary_address: str,
            primary_name: str,
            secondary_name: str,
            before: str,
            after: str,
        ) -> str:
            """Record a decompiled function pair judged relevant to the CVE.

            Addresses are hex strings (``0x...`` accepted). ``before`` is the
            pseudocode from the *secondary* (previous) binary, ``after`` from
            the *primary* (patched) binary. Returns a short status string.
            """
            if len(findings) >= MAX_FINDINGS:
                return (
                    f"finding budget exhausted ({MAX_FINDINGS}); stop recording "
                    f"and wrap up"
                )
            try:
                addr1_int = int(primary_address, 16)
            except ValueError:
                return f"invalid primary_address: {primary_address!r}"

            udiff = "\n".join(
                difflib.unified_diff(
                    before.splitlines(),
                    after.splitlines(),
                    fromfile=f"{secondary_name} before",
                    tofile=f"{primary_name} after",
                    lineterm="",
                )
            )
            parents = json.dumps(
                next(
                    discover_parents(artifact.diff.secondary.get(addr1_int)),
                    None,
                )
            )
            findings.append(
                DecompiledFunction(
                    before=before,
                    after=after,
                    udiff=udiff,
                    metadata=DecompiledFunctionMetadata(
                        file=artifact.primary_file.name,
                        name=primary_name,
                        address=f"{addr1_int:X}",
                        parents=parents,
                    ),
                )
            )
            return f"recorded ({len(findings)}/{MAX_FINDINGS})"

        msrc = context.cve_details.msrc_report
        system = SYSTEM_PROMPT.format(
            max_worklist=MAX_WORKLIST,
            max_findings=MAX_FINDINGS,
            primary_name=artifact.primary_file.name,
            secondary_name=artifact.secondary_file.name,
            cve=context.cve_details.cve,
            title=getattr(msrc, "title", "") or "",
            description=getattr(msrc, "description", "") or "",
            worklist=self._format_worklist(artifact),
        )

        console.info(
            f"[*] MCP investigation of {artifact.primary_file.name} "
            f"({len(artifact.changed)} changed, worklist "
            f"{min(len(artifact.changed), MAX_WORKLIST)})"
        )

        with Timer(f"mcp investigation of {artifact.primary_file.name}"):
            async with IdaMcpLauncher() as launcher:
                primary_url, secondary_url = await launcher.start_pair(
                    primary_i64, secondary_i64
                )
                mcp_tools = await build_mcp_tools(primary_url, secondary_url)
                tools = [*mcp_tools, record_finding]

                llm = AgentModels.reverse_engineering_model.model
                react = create_react_agent(llm, tools)

                await react.ainvoke(
                    {
                        "messages": [
                            SystemMessage(content=system),
                            HumanMessage(
                                content=(
                                    f"Investigate the worklist for "
                                    f"{artifact.primary_file.name} and record "
                                    f"security-relevant findings via "
                                    f"record_finding."
                                )
                            ),
                        ]
                    },
                    {"recursion_limit": RECURSION_LIMIT},
                )

        console.info(
            f"[+] MCP investigation of {artifact.primary_file.name} "
            f"recorded {len(findings)} findings"
        )

        return {"mcp_results": [McpResult(artifact=artifact, decompiled=findings)]}
