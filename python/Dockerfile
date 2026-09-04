FROM python:3.12.10

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir \
		--index-url https://download.pytorch.org/whl/cpu \
		torch \
	&& pip install --no-cache-dir -r requirements.txt

COPY . .
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "main.py"]
