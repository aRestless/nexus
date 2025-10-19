FROM scratch

# Copy the statically compiled binary
COPY nexus /nexus

# Expose default port
EXPOSE 4240

# Run the binary
ENTRYPOINT ["/nexus"]

