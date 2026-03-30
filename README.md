#  Diagnostic Tool

Ferramenta de diagnóstico de conectividade para integração entre sistemas.

## 🔍 O que faz
- Teste de DNS
- Teste de porta TCP
- Verificação SSL
- Traceroute

## 🧠 Cenário de uso
Diagnóstico de falhas em integrações entre sistemas (APIs, gateways, serviços externos).

## ⚙️ Configuração

Crie um `.env`:
API_HOST=api.exemplo.com

## ▶️ Execução

python main.py --host api.exemplo.com

## 📊 Exemplo de saída
[DNS]
Status: OK
IPs resolvidos: 44.199.190.129
Mensagem: DNS resolvido
