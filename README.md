# Projeto de Segurança e Confiabilidade 2020/2021:
## SeiTchiz - An Instagram clone

A parte prática da disciplina de Segurança e Confiabilidade pretende familiarizar os alunos com alguns dos  problemas  envolvidos  na  programação  de  aplicações  distribuídas  seguras,  nomeadamente  a gestão  de  chaves  criptográficas,  a  geração  de  sínteses  seguras,  cifras  e  assinaturas  digitais,  e  a utilização de canais seguros à base do protocolo TLS. O projeto será realizado utilizando a linguagem de programação Java e a API de segurança do Java.

O trabalho consiste na concretização do sistema *SeiTchiz* (uma versão portuguesa do Instagram), que é um sistema do tipo cliente-servidor que permite que os utilizadores (clientes) utilizem um servidor central para partilhar fotografias e comunicar com outros utilizadores.

---

## Modelo de sistema e definições preliminares

A fim de simplificar o projeto, assumimos que todos os clientes têm  acesso a todas as chaves públicas do sistema. As chaves privadas  estarão armazenadas em **keystores** (uma por cada utilizador e uma para o servidor) protegidas por passwords. Adicionalmente, todas as   chaves  públicas estão disponíveis como ficheiros *cert* (certificados  no formato X509 auto-assinados) numa pasta com o nome `/PubKeys/`. Existe também uma truststore contendo o certificado da chave pública do servidor, acessível a todos os clientes.

Todos os pares de chaves serão gerados usando o algoritmo RSA de 2048 bits.

Cada grupo mantido pelo servidor usará  uma chave  de grupo simétrica AES para cifrar e decifrar mensagens trocadas nesse grupo. **A cifra será fim-a-fim**, i.e., ambas as operações de cifrar e decifrar são efetuadas pelo cliente.

Finalmente, de forma a maximizar ainda mais a confiança no ambiente de execução, o servidor armazena a lista de  utilizadores, a lista de seguidores de cada utilizador, e a  associação entre utilizadores e grupos, em ficheiros cifrados. A informação sobre likes e as próprias fotografias são cifradas. Contudo, o  servidor irá verificar a integridade das fotografias armazenadas.

Iremos utilizar também canais seguros (protocolo TLS/SSL) e a verificação da identidade do servidor à base de criptografia assimétrica. Desta forma, será garantida a **autenticidade** do servidor e a **confidencialidade** da comunicação entre cliente e servidor.

---

## Keystores

De forma a exemplificar a utilização do projeto, foram criadas algumas keystores de exemplo.

Criámos 5 utilizadores e as suas respetivas keystores, cada uma com a sua chave privada e pública, cujo certificado está presente no diretório `/PubKeys/` e também na `truststore.client` (localizada na root do projeto) onde tanto o servidor como qualquer cliente vão ter acesso. Os utilizadores e a localização da suas keystores são, nomeadamente:
- abc users/abc/abc.client
- abc2 users/abc2/abc2.client
- abc3 users/abc3/abc3.client
- abc4 users/abc4/abc4.client
- abc5 users/abc5/abc5.client

Existe também a keystore do servidor, `keystore.server`, na root do projeto. Todas as keystores aqui apresentadas têm como password **123456**.

---

## Execução

A execução dos ficheiros *.jar*, presentes na root do projeto, em conjunto com o ficheiro *.policy* respetivo é feita a partir dos seguintes comandos:

- **Servidor:**
  
  $ java -Djava.security.manager -Djava.security.policy=server.policy -jar SeiTchizServer.jar <porto><keystore><keystore.password>

- **Cliente:**
  
  $ java -Djava.security.manager -Djava.security.policy=client.policy -jar SeiTchiz.jar <serverAddress> <truststore> <keystore> <keystore.password> <ClientID>

### Exemplos de execução

De seguida apresentamos alguns comandos que servirão de exemplos de execução do projeto, utilizando os clientes previamente definidos:

- **Servidor:** 
  
  $ java -Djava.security.manager -Djava.security.policy=server.policy -jar SeiTchizServer.jar 45678 keystore.server 123456

- **Clientes:** 
  
  $ java -Djava.security.manager -Djava.security.policy=client.policy -jar SeiTchiz.jar localhost:45678 truststore.client users/abc/abc.client 123456 abc

  $ java -Djava.security.manager -Djava.security.policy=client.policy -jar SeiTchiz.jar localhost:45678 truststore.client users/abc2/abc2.client 123456 abc2

  $ java -Djava.security.manager -Djava.security.policy=client.policy -jar SeiTchiz.jar localhost:45678 truststore.client users/abc3/abc3.client 123456 abc3

  $ java -Djava.security.manager -Djava.security.policy=client.policy -jar SeiTchiz.jar localhost:45678 truststore.client users/abc4/abc4.client 123456 abc4

  $ java -Djava.security.manager -Djava.security.policy=client.policy -jar SeiTchiz.jar localhost:45678 truststore.client users/abc5/abc5.client 123456 abc

---

## Decisões de Design

O enunciado do projeto especificava que cada cliente iria ter uma *truststore* com todas as chaves de todos os clientes, e também do servidor. Decidimos, por uma questão de simplificação, criar apenas uma *truststore*, a ser utilizada pelo servidor e pelos clientes, com todas as chaves de todos os participantes.

A encriptação do ficheiro `users.txt`, utilizado pelo servidor no processo de autenticação do cliente, é feita a partir de uma **chave simétrica** AES, criada na primeira utilização do método autenticar (quando `users.txt` é criado pela primeira vez) e guardada num ficheiro à parte, `keyfile.txt`. De maneira a esta chave não ser guardada em claro, ela mesmo é encriptada com a chave pública do servidor e é assim escrita em `keyfile.txt`, e quando necessário é desencriptada com a chave privada do servidor.

O ficheiro `cliente.policy` especifica que o cliente tem permissão de read para todos os ficheiro no sistema. Isto deve-se ao facto do comando *post* da aplicação *SeiTchiz*, onde entendemos que seria possível fornecer uma fotografia que estaria presente em qualquer lugar do sistema.
  
---

## Autores

Projeto realizado por Grupo 06:

- **João Cotralha** Nº51090
- **Ezequiel Barreira** Nº44768
