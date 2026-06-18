from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from veeam_parser import parse_log

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB

ALLOWED_EXTENSIONS = {'log', 'txt'}


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/parse', methods=['POST'])
def api_parse():
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400

    files = request.files.getlist('files')
    results = []

    for f in files:
        if not f or f.filename == '':
            continue
        if not allowed_file(f.filename):
            results.append({'filename': f.filename, 'error': 'Unsupported file type'})
            continue
        try:
            content = f.stream.read().decode('utf-8', errors='replace')
            sessions = parse_log(secure_filename(f.filename), content)
            if not sessions:
                results.append({'filename': f.filename, 'error': 'Keine parsebaren Einträge gefunden'})
            else:
                results.extend(sessions)
        except Exception as e:
            results.append({'filename': f.filename, 'error': str(e)})

    return jsonify(results)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
