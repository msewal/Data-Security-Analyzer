# Python 3.11 tabanlı minimal imaj
FROM python:3.11-slim

# Çalışma dizini
WORKDIR /app

# Projeyi kopyala
COPY . /app

# pip güncelle, bağımlılıkları yükle
RUN pip install --upgrade pip && pip install -r requirements.txt

# Django statik dosyaları topla
RUN python manage.py collectstatic --noinput

# 8000 portunu aç
EXPOSE 8000

# Gunicorn ile başlat
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "wfe.wsgi:application"] 