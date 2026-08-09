"""SQLite persistence for claim graphs (one row per audit run)."""
import aiosqlite, time
from .claim_graph import ClaimGraph

SCHEMA = """CREATE TABLE IF NOT EXISTS runs(
  id TEXT PRIMARY KEY, repo TEXT, created REAL, graph_json TEXT)"""

class GraphStore:
    def __init__(self, path: str = "swarm.db"):
        self.path = path

    async def save(self, run_id: str, repo: str, graph: ClaimGraph) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(SCHEMA)
            await db.execute(
                "INSERT OR REPLACE INTO runs VALUES(?,?,?,?)",
                (run_id, repo, time.time(), graph.to_json()))
            await db.commit()

    async def load(self, run_id: str):
        async with aiosqlite.connect(self.path) as db:
            await db.execute(SCHEMA)
            cur = await db.execute("SELECT graph_json FROM runs WHERE id=?", (run_id,))
            row = await cur.fetchone()
            return ClaimGraph.from_json(row[0]) if row else None
