from langchain_core.tools import BaseTool
from langchain_mcp_adapters.client import MultiServerMCPClient


READ_ONLY_TOOLS = frozenset(
    {
        "decompile",
        "disasm",
        "lookup_funcs",
        "get_bytes",
        "get_int",
        "get_string",
        "xrefs_to",
        "callees",
        "find_regex",
        "find_bytes",
        "idalib_current",
    }
)

_SERVER_KEYS = ("primary", "secondary")


def _is_read_only(name: str) -> bool:
    for key in _SERVER_KEYS:
        prefix = f"{key}_"
        if name.startswith(prefix):
            return name[len(prefix):] in READ_ONLY_TOOLS
    return name in READ_ONLY_TOOLS


async def build_mcp_tools(primary_url: str, secondary_url: str) -> list[BaseTool]:
    """Connect to two idalib-mcp servers and return their read-only tools.

    langchain-mcp-adapters prefixes each tool name with the connection key
    (``primary_decompile`` / ``secondary_decompile``), so the model can target
    a specific binary side.
    """
    client = MultiServerMCPClient(
        {
            "primary":   {"url": primary_url,   "transport": "sse"},
            "secondary": {"url": secondary_url, "transport": "sse"},
        }
    )
    tools = await client.get_tools()
    return [t for t in tools if _is_read_only(t.name)]
