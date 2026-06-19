import uvicorn

if __name__ == "__main__":
    # Run the FastAPI app from the correct module path
    uvicorn.run("agentsecgov.src.agentsecgov.main:app", host="0.0.0.0", port=8000, reload=True)
