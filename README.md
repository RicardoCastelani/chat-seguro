# Chat Seguro - Criptografia e Segurança

## Integrantes
- [Ricardo] RA [1125087]
- [Tomas] RA [1125129]

## 📘 Descrição
Este projeto é um sistema de chat seguro que garante **confidencialidade** e **integridade** das mensagens trocadas entre dois usuários.

Utiliza criptografia **simétrica (AES)** e **HMAC com SHA-256** para autenticação e verificação da integridade das mensagens.

## 🔐 Tecnologias e Algoritmos Utilizados
- **Python 3**
- **Sockets TCP** (para comunicação entre clientes e servidor)
- **AES (modo CFB)** – Criptografia simétrica
- **HMAC (SHA-256)** – Garantia de integridade
- **PBKDF2HMAC** – Derivação de chave a partir de senha compartilhada
- **Biblioteca `cryptography`**

## ⚙️ Como Executar

1. Instale a biblioteca necessária:
```bash
pip install cryptography
