# eBPF Helper - Projeto de Engenharia Informática

## How to use
### Gatherer 
```
python gather.py
```

### AI Agent
Place logs from the eBPF verifier inside the Logs folder and run:
```
python eBPF_Helper.py ./Logs/<name>.log
```
You can also give the source code by placing it in the Programs folder and running:
```
python eBPF_Helper.py ./Logs/<name>.log ./Programs/<name>.bpf.c
```
