FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install flask python-nmap
EXPOSE 5000
CMD ["python", "riskeye.py"]
