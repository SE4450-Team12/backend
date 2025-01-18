from typing import Optional, List, Dict
from pydantic import BaseModel, Field
from bson import ObjectId
from pydantic.json_schema import JsonSchemaValue

class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, value, info):
        if not ObjectId.is_valid(value):
            raise ValueError(f"Invalid ObjectId: {value}")
        return ObjectId(value)

    @classmethod
    def __get_pydantic_json_schema__(cls, schema: JsonSchemaValue, handler) -> JsonSchemaValue:
        # Call the handler to ensure compatibility with Pydantic's schema logic
        json_schema = handler(schema)
        # Modify the schema to represent this as a string type
        json_schema.update(type="string")
        return json_schema

    @classmethod
    def __pydantic_modify_json_schema__(cls, schema: dict) -> None:
        schema.update(type="string")

class Profile(BaseModel):
    name: str
    about: str


class User(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    username: str
    password: str
    salt: str
    profile: Profile
    dh_keys: List[Dict[str, str]] = Field(default=[])

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}
        json_schema_extra = {
            "example": {
                "username": "john_doe",
                "password": "securepassword",
                "salt":"hashed_salt",
                "profile": {
                    "name": "John Doe",
                    "about": "A software engineer passionate about AI.",
                },
            }
        }

class UserResponse(User):
    password: Optional[str] = Field(default=None, exclude=True)

    class Config:
        json_encoders = {ObjectId: str}
        json_schema_extra = {
            "example": {
                "_id": "507f191e810c19729de860ea",
                "username": "john_doe",
                "profile": {
                    "name": "John Doe",
                    "about": "A software engineer passionate about AI."
                }
            }
        }

class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str
