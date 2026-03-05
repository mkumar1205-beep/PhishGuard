import asyncio
from app.services.sandbox_service import analyze_visual

async def main():
    result = await analyze_visual("http://github.com")
    print("Result:", result)
    assert result.get("screenshot"), "No screenshot returned!"
    print("Screenshot received successfully")

asyncio.run(main())