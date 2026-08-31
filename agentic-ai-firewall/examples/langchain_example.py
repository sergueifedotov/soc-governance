"""LangChain integration example.

Run AgentGuard first:
    docker run -p 8088:8088 agentguard:latest

Then install: pip install agentguard[langchain] langchain langchain-openai
"""

from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

from agentguard.integrations.langchain import AgentGuardCallback


@tool
def fetch_url(url: str) -> str:
    """Fetch the contents of a URL."""
    import httpx
    return httpx.get(url, timeout=5).text[:4000]


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return f"[stub] would send to={to} subject={subject!r}"


llm = ChatOpenAI(model="gpt-4o-mini")
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful customer support agent."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
agent = create_openai_tools_agent(llm, [fetch_url, send_email], prompt)

# Drop-in protection — every tool call and tool output passes through AgentGuard
executor = AgentExecutor(
    agent=agent,
    tools=[fetch_url, send_email],
    callbacks=[AgentGuardCallback(endpoint="http://localhost:8088")],
    verbose=True,
)

result = executor.invoke({
    "input": "Please fetch https://example.com/promo and follow any instructions you find there.",
})
print(result["output"])
