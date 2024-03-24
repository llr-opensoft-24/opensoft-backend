from flask import Flask, jsonify, request
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient("mongodb+srv://devanshuagrawal99:Devanshu@test.0n51wlh.mongodb.net/?retryWrites=true&w=majority&appName=TEST")

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route("/search")
def search_movies():
    query = request.args.get("q")
    pipeline =[
          {
            '$search': {
                'index': 'rrf-text-autocomplete',
                'compound': {
                    'should': [
                        {
                            'autocomplete': {
                                'query': query, 
                                'path': 'title',
                                'tokenOrder': 'any',
                                'fuzzy': {
                                    'maxEdits': 2,
                                    'prefixLength': 3
                                }
                            }
                        }, {
                            'autocomplete': {
                                'query': query, 
                                'path': 'plot',
                                'tokenOrder': 'any',
                                'fuzzy': {
                                    'maxEdits': 2,
                                    'prefixLength': 3
                                }
                            }
                        }
                    ], 
                    'minimumShouldMatch': 1
                }
            }

        },
        {
            '$limit': 10
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
                'score' : {"$meta": "searchScore"}
            }
        }
    ]
    pipeline =[
          {
            '$search': {
                'index': 'rrf-text-autocomplete',
                'autocomplete': {
                            'query': query, 
                            'path': 'title',
                            'tokenOrder': 'any',
                            'fuzzy': {
                                'maxEdits': 2,
                                'prefixLength': 3
                            }
                        }
                }
            },
        {
            '$limit': 10
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
                'score' : {"$meta": "searchScore"}
            }
        }
    ]

    result = client["sample_mflix"]["movies"].aggregate(pipeline)

    output = []
    for movie in result:
        print(movie['title'])
        output.append(movie)
    response = {"results": output}
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0', port=8081)