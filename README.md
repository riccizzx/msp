* Running the container for the first time: 
  * `cd docker/`
  * `docker build -t sgc .`
  * `docker run --name sgc -ti sgc`
  
* Running the container afterwards:
  * `docker start sgc`
  * `docker exec -ti sgc /bin/bash`