#!/bin/bash

# Use Jekyll's built-in server (handles routes correctly)
echo "Starting Jekyll server on http://localhost:4000"
echo "Press Ctrl+C to stop the server"
echo ""
bundle exec jekyll serve --host 0.0.0.0 --port 4000

