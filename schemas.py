from pydantic import BaseModel

class UserBase(BaseModel):
    name: str
    email: str

class UserCreate(UserBase):
    pass

class User(UserBase):
    id: int

    class Config:
        from_attributes = True

class NoteBase(BaseModel):
    content: str

class Note(NoteBase):
    id: int

class NoteCreate(NoteBase):
    pass
