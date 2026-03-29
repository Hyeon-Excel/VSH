FROM python:3.11-slim
WORKDIR /app
COPY routes/ /app/routes/
COPY app.py /app/app.py
RUN pip install flask --no-cache-dir
CMD ["python", "app.py"]