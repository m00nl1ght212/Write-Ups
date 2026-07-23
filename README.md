<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Press+Start+2P&size=20&duration=3000&pause=1000&color=9BBC0F&center=true&vCenter=true&width=600&height=60&lines=WRITEUPS;HTB+%C2%B7+THM+%C2%B7+VULNYX" alt="Typing SVG" />

<br>

![HTB](https://img.shields.io/badge/HACK%20THE%20BOX-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=black&labelColor=0F380F)
![THM](https://img.shields.io/badge/TRYHACKME-FF3E3E?style=for-the-badge&logo=tryhackme&logoColor=white&labelColor=0F380F)
![Vulnyx](https://img.shields.io/badge/VULNYX-9BBC0F?style=for-the-badge&logo=linux&logoColor=black&labelColor=0F380F)

![Machines](https://img.shields.io/badge/machines%20cleared-XX-9BBC0F?style=flat-square&labelColor=0F380F)
![Status](https://img.shields.io/badge/status-grinding-8BAC0F?style=flat-square&labelColor=0F380F)
![License](https://img.shields.io/badge/license-MIT-8B8B8B?style=flat-square&labelColor=0F380F)

</div>

<br>

## 🕹️ About

Welcome to my writeup log — a growing collection of solved machines and challenges from **Hack The Box**, **TryHackMe**, and **Vulnyx**.

Each entry documents the full run: recon → exploitation → privilege escalation → flags.

> ⚠️ Writeups for active HTB machines are published only after they're retired.

<br>

## 🗺️ Structure

```
writeups/
├── HTB/
│   ├── Easy/
│   ├── Medium/
│   ├── Hard/       
│   └── Insane/
├── THM/
│   ├── Info/
│   ├── Easy/
│   ├── Medium/
│   ├── Hard/        
│   └── Insane/
├── Vulnyx/
│   ├── Low/
│   ├── Easy/
│   ├── Medium/       
│   └── Hard/
└── README.md
```

Each writeup covers:

| Stage | Description |
|---|---|
| 🔍 Recon | Port scanning, service enumeration |
| 🚪 Exploitation | Entry vector, initial foothold |
| 🔓 Privesc | Privilege escalation |
| 🏁 Flags | User & root/system |
| 🛠️ Tools | What was used to get there |

<br>

## 🏆 Machine index

### Hack The Box

| Machine | OS | Difficulty | Writeup |
|---|:---:|:---:|:---:|
| Example | 🐧 Linux | 🟢 Easy | [View](./HTB/Linux/example.md) |

### TryHackMe

| Room | Category | Difficulty | Writeup |
|---|:---:|:---:|:---:|
| Example | 🌐 Web | 🟢 Easy | [View](./THM/Rooms/example.md) |

### Vulnyx

| Machine | OS | Difficulty | Writeup |
|---|:---:|:---:|:---:|
| Alpine | 🐧 Linux | 🟢 Easy | [▶ Play](./Vulnyx/Easy/Alpine.md) |
| Bank | 🐧 Linux | 🟢 Easy | [▶ Play](./Vulnyx/Easy/Bank.md) |
| Brain | 🐧 Linux | 🟢 Easy | [▶ Play](./Vulnyx/Easy/Brain.md) |
| Care | 🐧 Linux | 🟢 Easy | [▶ Play](./Vulnyx/Easy/Care.md) |
| Explorer | 🐧 Linux | 🟢 Easy | [▶ Play](./Vulnyx/Easy/Explorer.md) |
| Goetia | 🐧 Linux | 🟢 Easy | [▶ Play](./Vulnyx/Easy/Goetia.md) |
| Northwing | 🐧 Linux | 🟢 Easy | [▶ Play](./Vulnyx/Easy/Northwing.md) |
| Open | 🐧 Linux | 🟢 Easy | [▶ Play](./Vulnyx/Easy/Open.md) |



<br>

## 🧰 Common tools

`nmap` `gobuster` `feroxbuster` `burpsuite` `linpeas` `winpeas` `impacket` `hashcat` `metasploit` `bloodhound`

<br>

## 📜 Methodology

1. **Recon** — discover ports, services, and versions
2. **Enumeration** — identify the attack surface
3. **Exploitation** — gain initial access
4. **Privilege escalation** — go from user to root
5. **Documentation** — log commands, screenshots, and lessons learned

<br>

## ⚖️ Disclaimer

All content here is for **educational purposes only**. Techniques shown should only be used in controlled, authorized environments (HTB, THM, Vulnyx labs, or with explicit permission). I take no responsibility for misuse of this content.

<div align="center">

⭐ If this repo is useful to you, consider giving it a star

</div>