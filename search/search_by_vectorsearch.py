from flask import Flask, jsonify, request
from pymongo import MongoClient
from openai import OpenAI

app = Flask(__name__)

client2 = OpenAI(api_key="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")
def get_embedding(text, model="text-embedding-ada-002"):
  return client2.embeddings.create(input = [text], model=model).data[0].embedding

client = MongoClient("mongodb+srv://devanshuagrawal99:Devanshu@test.0n51wlh.mongodb.net/?retryWrites=true&w=majority&appName=TEST")
db = client.sample_mflix  # Replace "sample_mflix" with your actual database name
collection = db.movies  # Replace "movies" with your actual collection name


@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response


# Test to search for data in the database
@app.route("/search")
def search_movies():
    print("SUCCESSFULLY REDIRECTED")
    query = request.args.get("q")
    query_vector = get_embedding(query)
    pipeline = [
      {
        '$vectorSearch': {
          'index': 'rrf-vector-search', 
          'path': 'plot_embedding', 
          'queryVector': query_vector,
          'numCandidates': 150, 
          'limit': 10
        }
      }, 
      {
        '$project': {
          '_id': 0, 
          'plot': 1, 
          'title': 1, 
          'cast': 1,
          'genres': 1,
          'runtime': 1,
          'rated': 1,
          'cast': 1,
          'poster': 1,
          'fullplot': 1,
          'languages': 1,
          'released': 1,
          'directors': 1,
           'writer' : 1,
           'awards': 1,
           'year': 1,
           'imdb': 1,
           'countries': 1,
           'type': 1,
           'lastupdated': 1,
           'num_mflix_comments': 1,
          'score': {
            '$meta': 'vectorSearchScore'
          }
        }
      }
    ]

    result = client["sample_mflix"]["embedded_movies"].aggregate(pipeline)
    output = []
    for movie in result:
        print(movie["title"])
        output.append(movie)
    response = {"results": output}
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0', port=8081)