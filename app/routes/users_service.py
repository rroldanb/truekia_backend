from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from uuid import UUID, uuid4
from datetime import datetime, timedelta
from setuptools import setup, find_packages

setup(
    name="trueke-user-service",
    version="0.1.0",
    description="Microservicio de usuarios para la plataforma Trueke",
    author="GagoLabs",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
        "pydantic",
    ],
    python_requires=">=3.8",
)



app = FastAPI(title="User Service")

# Simulación de base de datos en memoria
fake_users_db = {}

# Modelos Pydantic
class UserProfile(BaseModel):
    id: UUID
    email: EmailStr
    first_name: str
    last_name: str
    phone: Optional[str]
    date_of_birth: Optional[str]
    profile_image_url: Optional[str]
    biography: Optional[str]
    is_verified: bool = False
    created_at: datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str

class UserSkill(BaseModel):
    id: UUID
    user_id: UUID
    skill_name: str
    skill_level: int
    years_experience: int
    is_verified: bool = False

# Autenticación (simulada)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def fake_hash_password(password: str):
    """
    Simula el hash de una contraseña.

    Parameters
    ----------
    password : str
        Contraseña en texto plano.

    Returns
    -------
    str
        Contraseña hasheada simulada.
    """
    return "hashed_" + password

def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Obtiene el usuario actual autenticado a partir del token.

    Parameters
    ----------
    token : str
        Token de autenticación.

    Returns
    -------
    dict
        Diccionario con los datos del usuario autenticado.

    Raises
    ------
    HTTPException
        Si el token no es válido o el usuario no existe.
    """
    user = next((u for u in fake_users_db.values() if u["token"] == token), None)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    return user

# Endpoints de autenticación
@app.post("/auth/register", status_code=201)
def register(user: UserCreate):
    """
    Registra un nuevo usuario.

    Parameters
    ----------
    user : UserCreate
        Datos del usuario a registrar.

    Returns
    -------
    dict
        ID y email del usuario registrado.

    Raises
    ------
    HTTPException
        Si el email ya está registrado.
    """
    if user.email in fake_users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = uuid4()
    fake_users_db[user.email] = {
        "id": user_id,
        "email": user.email,
        "password_hash": fake_hash_password(user.password),
        "first_name": user.first_name,
        "last_name": user.last_name,
        "is_verified": False,
        "created_at": datetime.utcnow(),
        "token": None,
        "skills": []
    }
    return {"id": user_id, "email": user.email}

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Inicia sesión de usuario y retorna un token de acceso.

    Parameters
    ----------
    form_data : OAuth2PasswordRequestForm
        Formulario con email y contraseña.

    Returns
    -------
    dict
        Token de acceso y tipo de token.

    Raises
    ------
    HTTPException
        Si las credenciales son incorrectas.
    """
    user = fake_users_db.get(form_data.username)
    if not user or user["password_hash"] != fake_hash_password(form_data.password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = str(uuid4())
    user["token"] = token
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/logout")
def logout(current_user: dict = Depends(get_current_user)):
    """
    Cierra la sesión del usuario actual.

    Parameters
    ----------
    current_user : dict
        Usuario autenticado.

    Returns
    -------
    dict
        Mensaje de confirmación de logout.
    """
    current_user["token"] = None
    return {"message": "Logged out"}

@app.post("/auth/refresh")
def refresh_token(current_user: dict = Depends(get_current_user)):
    """
    Refresca el token de acceso del usuario autenticado.

    Parameters
    ----------
    current_user : dict
        Usuario autenticado.

    Returns
    -------
    dict
        Nuevo token de acceso y tipo de token.
    """
    token = str(uuid4())
    current_user["token"] = token
    return {"access_token": token, "token_type": "bearer"}

# Endpoints de perfil
@app.get("/users/profile", response_model=UserProfile)
def get_profile(current_user: dict = Depends(get_current_user)):
    """
    Obtiene el perfil del usuario autenticado.

    Parameters
    ----------
    current_user : dict
        Usuario autenticado.

    Returns
    -------
    UserProfile
        Perfil del usuario.
    """
    return UserProfile(
        id=current_user["id"],
        email=current_user["email"],
        first_name=current_user["first_name"],
        last_name=current_user["last_name"],
        phone=None,
        date_of_birth=None,
        profile_image_url=None,
        biography=None,
        is_verified=current_user["is_verified"],
        created_at=current_user["created_at"]
    )

@app.put("/users/profile", response_model=UserProfile)
def update_profile(profile: UserProfile, current_user: dict = Depends(get_current_user)):
    """
    Actualiza el perfil del usuario autenticado.

    Parameters
    ----------
    profile : UserProfile
        Datos actualizados del perfil.
    current_user : dict
        Usuario autenticado.

    Returns
    -------
    UserProfile
        Perfil actualizado.
    """
    current_user.update(profile.dict(exclude_unset=True))
    return UserProfile(**current_user)

@app.get("/users/{user_id}", response_model=UserProfile)
def get_user(user_id: UUID):
    """
    Obtiene el perfil de un usuario por su ID.

    Parameters
    ----------
    user_id : UUID
        ID del usuario.

    Returns
    -------
    UserProfile
        Perfil del usuario.

    Raises
    ------
    HTTPException
        Si el usuario no existe.
    """
    for user in fake_users_db.values():
        if user["id"] == user_id:
            return UserProfile(
                id=user["id"],
                email=user["email"],
                first_name=user["first_name"],
                last_name=user["last_name"],
                phone=None,
                date_of_birth=None,
                profile_image_url=None,
                biography=None,
                is_verified=user["is_verified"],
                created_at=user["created_at"]
            )
    raise HTTPException(status_code=404, detail="User not found")

# Endpoints de skills
@app.post("/users/skills", response_model=UserSkill)
def add_skill(skill: UserSkill, current_user: dict = Depends(get_current_user)):
    """
    Agrega una habilidad al usuario autenticado.

    Parameters
    ----------
    skill : UserSkill
        Habilidad a agregar.
    current_user : dict
        Usuario autenticado.

    Returns
    -------
    UserSkill
        Habilidad agregada.
    """
    skill.id = uuid4()
    skill.user_id = current_user["id"]
    current_user["skills"].append(skill.dict())
    return skill

@app.get("/users/{user_id}/skills", response_model=List[UserSkill])
def get_skills(user_id: UUID):
    """
    Obtiene las habilidades de un usuario por su ID.

    Parameters
    ----------
    user_id : UUID
        ID del usuario.

    Returns
    -------
    List[UserSkill]
        Lista de habilidades del usuario.

    Raises
    ------
    HTTPException
        Si el usuario no existe.
    """
    for user in fake_users_db.values():
        if user["id"] == user_id:
            return [UserSkill(**s) for s in user.get("skills", [])]
    raise HTTPException(status_code=404, detail="User not found")

@app.delete("/users/skills/{skill_id}")
def delete_skill(skill_id: UUID, current_user: dict = Depends(get_current_user)):
    """
    Elimina una habilidad del usuario autenticado.

    Parameters
    ----------
    skill_id : UUID
        ID de la habilidad a eliminar.
    current_user : dict
        Usuario autenticado.

    Returns
    -------
    dict
        Mensaje de confirmación.

    Raises
    ------
    HTTPException
        Si la habilidad no se encuentra.
    """
    skills = current_user.get("skills", [])
    for i, s in enumerate(skills):
        if s["id"] == str(skill_id):
            del skills[i]
            return {"message": "Skill deleted"}
    raise HTTPException(status_code=404, detail="Skill not found")