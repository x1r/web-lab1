from database import engine
from models.user import Base

# Создаем все таблицы
Base.metadata.create_all(bind=engine)
