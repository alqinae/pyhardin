#!/bin/bash
source .venv/bin/activate
# Test 1: Start prompt generation scan
curl -X POST http://localhost:8000/scan -H "Authorization: Basic YWRtaW46YWRtaW4="

# Wait for generation to simulate real world
sleep 5

# Test 2: Execute all pending prompts
curl -X POST http://localhost:8000/analyze-all -H "Authorization: Basic YWRtaW46YWRtaW4="
