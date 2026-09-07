FROM ollama/ollama:latest

COPY entrypoint.sh /entrypoint.sh

# delete CR characters
RUN sed -i 's/\r$//' /entrypoint.sh && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]