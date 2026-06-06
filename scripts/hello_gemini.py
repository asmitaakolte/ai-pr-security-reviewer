from google import genai

client = genai.Client()  # auto-reads GEMINI_API_KEY from the environment
resp = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="Reply with exactly: setup OK",
)
print(resp.text)