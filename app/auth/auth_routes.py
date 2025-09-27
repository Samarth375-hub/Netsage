from fastapi import APIRouter, HTTPException
from datetime import timedelta
from app.db.DB_Setup import UserDBHandler
from app.auth.auth_utils import create_access_token,create_refresh_token,get_current_user,verify_refresh_token
from app.schemas.user import RegisterRequest, LoginRequest,TokenResponse
import pdb
import time


router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
userdbhandler = UserDBHandler()



@router.post("/register")
async def create_user(request: RegisterRequest):
    t1 = time.time()

    # t_check_start = time.time()
    # user = await userdbhandler.get_existing_user(request.email)
    # print("get_existing_user took", time.time() - t_check_start, "seconds")

    # if user:
    #     raise HTTPException(status_code=409, detail="User already exists")

    t_insert_start = time.time()
    result = await userdbhandler.create_user(
        username=request.username,
        email=request.email,
        password=request.password,
        full_name=request.full_name,
        role=request.role
    )
    if not result:
        raise HTTPException(status_code=409, detail="User already exists")
    print("create_user insert took", time.time() - t_insert_start, "seconds")

    process_time = time.time() - t1
    return {
        "message": "User created successfully",
        "user_id": result["id"],
        "api_response_time": f"{process_time:.4f} seconds"
    }

@router.post("/login",response_model=TokenResponse)
async def login_user(request: LoginRequest):
    user = await userdbhandler.get_existing_user(request.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found, please sign up first!")

    if not userdbhandler.verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid password!")

    access_token = create_access_token(
        data={"sub": user["email"], "user_id": user["id"], "role": user["role"]}
    )
    
    refresh_token = create_refresh_token(
        data={"sub": user["email"], "user_id": user["id"]},
        expires_delta=timedelta(days=7)
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        username=user["username"],
        email=user["email"],
        role=user["role"]
    )

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(refresh_token: str):
    # Step 1: Verify refresh token
    payload = verify_refresh_token(refresh_token)
    user_id = payload.get("user_id")
    email = payload.get("sub")

    if not user_id or not email:
        raise HTTPException(status_code=401, detail="Invalid refresh token payload")

    # Step 2: Get user again from DB
    user = await userdbhandler.get_existing_user(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Step 3: Generate new tokens
    new_access_token = create_access_token(
        {"sub": user["email"], "user_id": user["id"], "role": user["role"]}
    )
    new_refresh_token = create_refresh_token(
        {"sub": user["email"], "user_id": user["id"]}
    )

    # Step 4: Return new tokens
    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        username=user["username"],
        email=user["email"],
        role=user["role"],
    )