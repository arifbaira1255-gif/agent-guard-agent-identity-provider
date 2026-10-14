# Deploy the prototype (about 10 minutes)
1. Create a new GitHub repo (private is fine) and push this folder's contents to it.
2. Render dashboard -> New -> Blueprint -> pick the repo. It reads render.yaml and creates both services.
3. When both are live, check https://<backend>.onrender.com/health and open the frontend URL.
4. If the backend URL is not exactly aql-backend.onrender.com, update NEXT_PUBLIC_API_URL and
   NEXT_PUBLIC_API_BASE_URL on the frontend and redeploy it.
Notes: no API keys are needed for the demo (LLM, Pinecone and Supabase have local fallbacks).
Code execution stays disabled. Free-tier services sleep after idle, so the first request is slow.
