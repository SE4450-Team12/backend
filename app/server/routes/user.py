from fastapi import APIRouter, Body, Response, status, HTTPException, Depends
from fastapi.encoders import jsonable_encoder
from bson import ObjectId
from os import getenv
from jose import jwt
from datetime import datetime, timedelta


from app.server.database import get_db
from app.server.models.user import User, UserResponse, UserLogin, UserRegister
from app.server.middleware.auth import authenticate_user
from app.server.middleware.hash import hash_password, verify_password

db = get_db()

router = APIRouter()

SECRET_KEY = getenv("JWT_SECRET")
ALGORITHM = getenv("JWT_ALGO")

#@route GET api/user/test
#@description Test user route
#@access Public
@router.get("/test")
async def read_users():
    return {"message": "Users endpoint"}


#@route GET /api/user/test-login
#@description Test if the user is logged in by validating the JWT token
#@access Private
@router.get("/test-login")
async def test_login(response: Response, payload: dict = Depends(authenticate_user)):
    response.status_code = status.HTTP_200_OK
    return {
        "message": "Login successful!",
        "user_id": payload.get("user_id"),
        "issued_at": payload.get("iat"),
        "expires_at": payload.get("exp"),
    }

#@route POST api/user
#@description Create a user
#@access Public
@router.post("/", response_model=UserResponse)
async def create_user(user: UserRegister, response: Response):
    user_dict = user.dict(by_alias=True)
    new_user = user_dict
    username = user_dict["username"]
    arr = await db["Users"].find({"username":username}).to_list()
    if len(arr) > 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists!")
    hash = hash_password(user_dict["password"])
    new_user["password"] = hash["hashed_password"]
    new_user["salt"] = hash["salt"]
    new_user["profile"] = {"name":"", "about":""}
    result = await db["Users"].insert_one(new_user)
    user_dict["_id"] = result.inserted_id
    response.status_code = status.HTTP_200_OK
    
    return user_dict

#@route POST /api/user/login
#@description Logs user in and returns JWT
#@access Public
@router.post("/login")
async def login(user_login: UserLogin, response: Response):

    user = await db["Users"].find_one({"username": user_login.username})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email or Password is incorrect."
        )

    if not verify_password(user_login.password, user["salt"], user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email or Password is incorrect."
        )

    
    expiration = datetime.utcnow() + timedelta(minutes=15)
    payload = {
        "user_id": str(user["_id"]),
        "exp": expiration,
        "iat": datetime.utcnow(),
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    
    response.status_code = status.HTTP_200_OK
    return {
        "message": f"{user['profile']['name']} has been logged in successfully.",
        "token": token,
    }

#@route GET api/user
#@description Get all users
#@access Protected
@router.get("/", response_model=list[User])
async def get_all_users(
    response: Response,
    payload: dict = Depends(authenticate_user)
):
    users = await db["Users"].find().to_list()
    response.status_code = status.HTTP_200_OK
    return users

#@route GET api/user/{user_id}
#@description Get User by ID
#@access Protected
@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str, 
    response: Response, 
    payload: dict = Depends(authenticate_user)
):
    user = await db["Users"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found!"
        )
    response.status_code = status.HTTP_200_OK
    return user

#@route PUT api/user
#@description Update the authenticated user's information
#@access Protected
@router.put("/", response_model=UserResponse)
async def update_user(
    user: dict, 
    response: Response, 
    payload: dict = Depends(authenticate_user)
):
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload."
        )
    
    update_result = await db["Users"].update_one(
        {"_id": ObjectId(user_id)}, {"$set": jsonable_encoder(user)}
    )
    if update_result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found!"
        )
    
    updated_user = await db["Users"].find_one({"_id": ObjectId(user_id)})
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found after update!"
        )
    
    response.status_code = status.HTTP_200_OK
    return updated_user


#@route DELETE api/user/{user_id}
#@description Delete a user by ID
#@access Protected
@router.delete("/{user_id}", response_model=str)
async def delete_user(
    user_id: str, 
    response: Response, 
    payload: dict = Depends(authenticate_user)
):
    if payload["user_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to delete this user."
        )
    
    delete_result = await db["Users"].delete_one({"_id": ObjectId(user_id)})
    if delete_result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found!"
        )
    
    response.status_code = status.HTTP_200_OK
    return "User deleted."

#@route PUT api/user/dh_keys
#@description Overwrites the authenticated user's dh_keys array with a new array
#@access Private
@router.put("/dh_keys", response_model=str)
async def update_dh_keys(dh_keys: list[dict], response: Response, payload: dict = Depends(authenticate_user)):
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload.",
        )

    user = await db["Users"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found!",
        )

    if not isinstance(dh_keys, list) or any(not isinstance(key, dict) for key in dh_keys):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid format for Diffie-Hellman keys. Expected an array of objects.",
        )

    await db["Users"].update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"dh_keys": dh_keys}}
    )

    response.status_code = status.HTTP_200_OK
    return "Diffie-Hellman keys updated successfully."

#@route DELETE api/user/dh_key/{username}
#@description Pop a Diffie-Hellman key pair by username
#@access Protected
@router.delete("/dh_keys/{username}", response_model=dict)
async def pop_dh_key(
    username: str,
    response: Response,
    payload: dict = Depends(authenticate_user)
):
    target_user = await db["Users"].find_one({"username": username})
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found!"
        )
    
    authenticated_user = await db["Users"].find_one({"_id": ObjectId(payload["user_id"])})
    if not authenticated_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user not found!"
        )

    dh_keys = target_user.get("dh_keys", [])
    if not dh_keys:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No Diffie-Hellman keys available for this user."
        )

    popped_key = dh_keys.pop(0)

    await db["Users"].update_one(
        {"username": username},
        {"$set": {"dh_keys": dh_keys}}
    )

    response.status_code = status.HTTP_200_OK
    return {"popped_key": popped_key}


