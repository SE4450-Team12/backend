from fastapi import APIRouter, Depends, HTTPException, status, Response
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app.server.database import get_db
from app.server.models.chatroom import Chatroom, SentChatroom
from app.server.middleware.auth import authenticate_user
from app.server.middleware.socket import socket_manager
from app.server.middleware.utils import generate_chatroom_name

db = get_db()
router = APIRouter()

#@route GET api/chatroom/test
#@description Test chatroom route
#@access Public
@router.get("/test")
async def test():
    return "Chatroom route works."

#@route GET api/chatroom
#@description Get all chatrooms the user is in
#@access Protected
@router.get("/", response_model=list[dict])
async def get_user_chatrooms(
    response: Response, 
    payload: dict = Depends(authenticate_user)
):
    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload."
        )

    chatrooms = await db["Chatrooms"].find({
        "members": ObjectId(user_id),
        "firstMessage": True
    }).to_list(None)

    formatted_chatrooms = []
    for chatroom in chatrooms:
        formatted_chatrooms.append({
            "_id": str(chatroom["_id"]),
            "name": await generate_chatroom_name(chatroom["members"], user_id),
            "members": [str(member) for member in chatroom["members"]]
        })

    response.status_code = status.HTTP_200_OK
    return formatted_chatrooms


#@route GET api/chatroom/{chatroom_id}
#@description Get a chatroom by ID
#@access Protected
@router.get("/{chatroom_id}", response_model=dict)
async def get_user_chatroom(
    chatroom_id: str, 
    response: Response, 
    payload: dict = Depends(authenticate_user)
):
    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload."
        )

    chatroom = await db["Chatrooms"].find_one(
        {"_id": ObjectId(chatroom_id), "members": ObjectId(user_id)}
    )

    if not chatroom:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chatroom not found or user is not a member."
        )

    response.status_code = status.HTTP_200_OK
    return {
        "_id": str(chatroom["_id"]),
        "name": await generate_chatroom_name(chatroom["members"], user_id),
        "members": [str(member) for member in chatroom["members"]]
    }


#@route POST api/chatroom
#@description Create a new chatroom
#@access Protected
@router.post("/", response_model=dict)
async def create_chatroom(
    chatroom: SentChatroom, 
    response: Response, 
    payload: dict = Depends(authenticate_user)
):
    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload."
        )

    chatroom_dict = chatroom.dict(by_alias=True)
    chatroom_dict["members"] = sorted(
        [ObjectId(user_id)] + [ObjectId(m) for m in chatroom_dict.get("members", [])]
    )

    existing_chatroom = await db["Chatrooms"].find_one({"members": chatroom_dict["members"]})

    if existing_chatroom:
        response.status_code = status.HTTP_200_OK
        return {
            "_id": str(existing_chatroom["_id"]),
            "name": await generate_chatroom_name(existing_chatroom["members"], user_id),
            "members": [str(member) for member in existing_chatroom["members"]]
        }
    
    chatroom_dict["firstMessage"] = False

    result = await db["Chatrooms"].insert_one(chatroom_dict)
    chatroom_dict["_id"] = str(result.inserted_id)

    chatroom_dict["name"] = await generate_chatroom_name(chatroom_dict["members"], user_id)
    chatroom_dict["members"] = [str(member) for member in chatroom_dict["members"]]

    for member in chatroom_dict["members"]:
        member_chatroom_name = await generate_chatroom_name(chatroom_dict["members"], member)
        chatroom_data = {
            "_id": chatroom_dict["_id"],
            "name": member_chatroom_name,
            "members": chatroom_dict["members"]
        }

    response.status_code = status.HTTP_201_CREATED
    return chatroom_dict




#@route POST api/chatroom/{chatroom_id}/join
#@description Add the authenticated user to the chatroom members list
#@access Protected
@router.post("/{chatroom_id}/join", response_model=str)
async def join_chatroom(
    chatroom_id: str, 
    response: Response, 
    payload: dict = Depends(authenticate_user)
):
    user_id = payload.get("user_id") 

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload."
        )

    chatroom = await db["Chatrooms"].find_one({"_id": ObjectId(chatroom_id)})
    if not chatroom:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chatroom not found!"
        )

    if ObjectId(user_id) in chatroom.get("members", []):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already a member of the chatroom!"
        )

    update_result = await db["Chatrooms"].update_one(
        {"_id": ObjectId(chatroom_id)},
        {"$addToSet": {"members": ObjectId(user_id)}}
    )

    if update_result.modified_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to add user to chatroom!"
        )

    response.status_code = status.HTTP_200_OK
    return f"User {user_id} successfully added to chatroom {chatroom_id}!"

#@route DELETE api/chatroom/{chatroom_id}
#@description Delete a chatroom and it's messages
#@access Protected
@router.delete("/{chatroom_id}", response_model=str)
async def delete_chatroom(
    chatroom_id: str, 
    response: Response, 
    payload: dict = Depends(authenticate_user)
):
    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload."
        )

    chatroom = await db["Chatrooms"].find_one({"_id": ObjectId(chatroom_id)})
    if not chatroom:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chatroom not found."
        )
    
    deleted_id = chatroom["_id"]
    members = list(chatroom["members"])
    isFirstMessage = chatroom["firstMessage"]

    if ObjectId(user_id) not in chatroom["members"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to delete this chatroom."
        )

    await db["Messages"].delete_many({"chatroom": ObjectId(chatroom_id)})

    delete_result = await db["Chatrooms"].delete_one({"_id": ObjectId(chatroom_id)})

    if delete_result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete chatroom."
        )
    
    if isFirstMessage:
        for member in members:
            chatroomName = await generate_chatroom_name(members,member)
            await socket_manager.emit(
                "chatroomDeleted",
                {"chatroomID": f"{deleted_id}", "chatroomName": f"{chatroomName}"},
                room=str(member) 
            )



    response.status_code = status.HTTP_200_OK
    return f"Chatroom {chatroom_id} successfully deleted."

#@route GET api/chatroom/{otherUserID}/{isSend}
#@description Retrieves user info
#@access Protected
@router.get("/{otherUserID}/{isSend}", response_model=dict)
async def get_user_crypto_info(
    otherUserID: str,
    isSend: str,
    response: Response,
    payload: dict = Depends(authenticate_user)
):
    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload.",
        )

    targetUser = await db["Users"].find_one({"_id": ObjectId(otherUserID)})

    if not targetUser:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found!",
        )

    user_data = {
        "_id": str(targetUser["_id"]),
        "username": targetUser["username"],
        "identityKey": targetUser["identityKey"],
        "schnorrKey": targetUser["schnorrKey"],
        "schnorrSig": targetUser["schnorrSig"],
    }

    if isSend == "send":
        otpKeys = targetUser.get("otpKeys", [])
        if not otpKeys:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No OTP keys available for this user."
            )

        poppedKey = otpKeys.pop(0)

        await db["Users"].update_one(
            {"_id": ObjectId(otherUserID)},
            {"$set": {"otpKeys": otpKeys}}
        )

        user_data["otpKey"] = poppedKey

    response.status_code = status.HTTP_200_OK
    return user_data



