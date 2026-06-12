import os
import json
import hashlib
import requests
from flask import Flask, render_template, request, redirect

app = Flask(__name__)

# Configurações
JSON_FILE = 'dados_temporarios.json'
# Pegue sua chave gratuita se cadastrando no site do VirusTotal
VIRUSTOTAL_API_KEY = '4fb4607ddb9a242f471c8b760252e4d44c2b5ebd8c688494b7a1ae44c3bda3b2' 

# Garante que o arquivo JSON exista ao iniciar
if not os.path.exists(JSON_FILE):
    with open(JSON_FILE, 'w') as f:
        json.dump([], f)

def carregar_historico():
    with open(JSON_FILE, 'r') as f:
        return json.load(f)

def salvar_no_historico(nome_arquivo, file_hash, status):
    historico = carregar_historico()
    historico.append({
        "nome": nome_arquivo,
        "hash": file_hash,
        "status": status
    })
    with open(JSON_FILE, 'w') as f:
        json.dump(historico, f, indent=4)

@app.route('/')
def index():
    historico = carregar_historico()
    return render_template('index.html', historico=historico)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'arquivo' not in request.files:
        return "Nenhum arquivo enviado", 400
    
    arquivo = request.files['arquivo']
    if arquivo.filename == '':
        return "Nenhum arquivo selecionado", 400

    # Ler os bytes do arquivo para gerar o Hash SHA-256
    conteudo = arquivo.read()
    sha256_hash = hashlib.sha256(conteudo).hexdigest()

    # --- CONSULTA À API DO VIRUSTOTAL ---
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    response = requests.get(url, headers=headers)
    status_resultado = "Desconhecido / Limpo"

    if response.status_code == 200:
        dados = response.json()
        # Pega a última análise feita por vários antivírus
        stats = dados['data']['attributes']['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        
        if malicious > 0:
            status_resultado = f"Malicioso ({malicious} detecções)"
        else:
            status_resultado = "Seguro"
    elif response.status_code == 404:
        # Se der 404, significa que o VirusTotal nunca viu esse arquivo antes. 
        # Na versão gratuita, você teria que fazer o upload do arquivo completo para eles analisarem.
        status_resultado = "Arquivo novo (Não encontrado na base de dados)"
    else:
        status_resultado = "Erro na verificação"

    # Salva os resultados no banco de dados JSON
    salvar_no_historico(arquivo.filename, sha256_hash, status_resultado)

    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)