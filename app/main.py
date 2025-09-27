from fastapi import FastAPI
from .auth import auth_routes as auth_routes
from .services import capture_routes as capture_routes

app = FastAPI()

# include routers
app.include_router(auth_routes.router)
app.include_router(capture_routes.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8001, reload=True)
