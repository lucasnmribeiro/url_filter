import requests
import tkinter as tk
from tkinter import messagebox

API_KEY = 'sua_api_key'
VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

def verificar_url(url):
    """Função que consulta a API do VirusTotal para verificar se a URL é maliciosa."""
    params = {'apikey': API_KEY, 'resource': url}
    response = requests.get(VIRUSTOTAL_URL, params=params)
    
    if response.status_code == 200:
        result = response.json()
        
        if result['response_code'] == 1:
            if result['positives'] > 0:
                return f"ALERTA: A URL {url} foi marcada como maliciosa!\nNúmero de antivírus que identificaram como maliciosa: {result['positives']}"
            else:
                return f"A URL {url} parece segura."
        else:
            return f"A URL {url} não foi encontrada no VirusTotal."
    else:
        return f"Erro ao consultar o VirusTotal: {response.status_code}"

def checar_url():
    """Função para pegar a URL da interface e exibir o resultado da verificação."""
    url = entry_url.get()
    if url:
        resultado = verificar_url(url)
        messagebox.showinfo("Resultado da Verificação", resultado)
    else:
        messagebox.showwarning("Entrada Inválida", "Por favor, insira uma URL válida.")

janela = tk.Tk()
janela.title("URLs_Filter")

label_instrucoes = tk.Label(janela, text="Digite a URL para verificar:")
label_instrucoes.pack(pady=10)

entry_url = tk.Entry(janela, width=50)
entry_url.pack(pady=10)

botao_verificar = tk.Button(janela, text="Verificar URL", command=checar_url)
botao_verificar.pack(pady=10)

janela.mainloop()