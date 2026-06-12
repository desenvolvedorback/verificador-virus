import os
import json
import hashlib
import requests
import time
from flask import Flask, render_template, request, redirect

app = Flask(__name__)

# Configurações
JSON_FILE = 'dados_temporarios.json'
VIRUSTOTAL_API_KEY = '4fb4607ddb9a242f471c8b760252e4d44c2b5ebd8c688494b7a1ae44c3bda3b2' 

# Garante que o arquivo JSON exista ao iniciar
if not os.path.exists(JSON_FILE):
    with open(JSON_FILE, 'w') as f:
        json.dump([], f)

def carregar_historico():
    with open(JSON_FILE, 'r') as f:
        return json.load(f)

def salvar_historico_completo(historico):
    with open(JSON_FILE, 'w') as f:
        json.dump(historico, f, indent=4)

def salvar_no_historico(nome_arquivo, file_hash, status):
    historico = carregar_historico()
    historico.append({
        "nome": nome_arquivo,
        "hash": file_hash,
        "status": status
    })
    salvar_historico_completo(historico)

# --- NOVA FUNÇÃO: ATUALIZA STATUS PENDENTES ---
def atualizar_status_pendentes():
    historico = carregar_historico()
    alterou = False
    
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    for item in historico:
        # Se o item ainda está esperando análise, tenta checar se já ficou pronto
        if item["status"] == "Enviado p/ Análise (Atualize a página em instantes)":
            url = f"https://www.virustotal.com/api/v3/files/{item['hash']}"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                dados = response.json()
                stats = dados['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                
                if malicious > 0:
                    item["status"] = f"Malicioso ({malicious} detecções)"
                else:
                    item["status"] = "Seguro"
                alterou = True
                
                # Pausa leve para respeitar o limite da API gratuita (4 requisições por minuto)
                time.sleep(0.5) 

    if alterou:
        salvar_historico_completo(historico)

@app.route('/')
def index():
    # Antes de carregar a página, verifica se as análises antigas já terminaram
    atualizar_status_pendentes()
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
        stats = dados['data']['attributes']['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        
        if malicious > 0:
            status_resultado = f"Malicioso ({malicious} detecções)"
        else:
            status_resultado = "Seguro"
            
    elif response.status_code == 404:
        # Se der 404, faz o upload do arquivo completo para análise
        url_upload = "https://www.virustotal.com/api/v3/files"
        
        arquivo.seek(0)
        files = {"file": (arquivo.filename, arquivo.stream, arquivo.content_type)}
        
        upload_response = requests.post(url_upload, headers=headers, files=files)
        
        if upload_response.status_code == 200:
            status_resultado = "Enviado p/ Análise (Atualize a página em instantes)"
        else:
            status_resultado = "Erro ao enviar arquivo para análise"
    else:
        status_resultado = "Erro na verificação"

    # Salva os resultados no banco de dados JSON
    salvar_no_historico(arquivo.filename, sha256_hash, status_resultado)

    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
