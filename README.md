

# 🧠 OSCP Command Toolbox

![GitHub Repo stars](https://img.shields.io/github/stars/uditchavda/oscp-command-tool?style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/uditchavda/oscp-command-tool?style=for-the-badge)
![GitHub license](https://img.shields.io/github/license/uditchavda/oscp-command-tool?style=for-the-badge)
![Built with HTML, CSS, JS](https://img.shields.io/badge/Built%20With-HTML%20%7C%20CSS%20%7C%20JavaScript-blueviolet?style=for-the-badge)

> A fully customizable, offline-ready, and beautifully designed OSCP cheat sheet web app to power up your offensive security game.

![Banner](https://raw.githubusercontent.com/uditchavda/oscp-command-tool/main/assets/oscp-banner.png)

---

## 🎯 Live Demo

🚀 [Try It Now – OSCP Command Toolbox](https://uditchavda.github.io/oscp-command-tool)

---

## ✨ Features

🔹 **Comprehensive Categories** – From Recon to Privilege Escalation and Pivoting, it's all here.  
🔹 **Dynamic Command Variables** – Auto-replace `<IP>`, `<PORT>`, `<LHOST>`, etc. across all commands.  
🔹 **Instant Search** – Find tools, sections, or keywords in a flash.  
🔹 **One-Click Copy** – Copy commands directly to clipboard.  
🔹 **100% Offline Usable** – Host locally or on GitHub Pages.  
🔹 **Hack-Themed UI** – Clean layout, dark mode, and OSCP vibes.

---

## 🖼️ Screenshots

### 📚 Main Interface  
![Main Interface](https://raw.githubusercontent.com/uditchavda/oscp-command-tool/main/assets/screenshots/main-interface.png)

### 🧠 Dynamic Command Input  
![Dynamic Inputs](https://raw.githubusercontent.com/uditchavda/oscp-command-tool/main/assets/screenshots/command-input.png)

---

## 🎞️ Demo GIF

![Demo GIF](https://raw.githubusercontent.com/uditchavda/oscp-command-tool/main/assets/screenshots/demo.gif)

---

## 🛠️ Local Setup

```bash
# Clone the repo
git clone https://github.com/uditchavda/oscp-command-tool.git

# Go to the project folder
cd oscp-command-tool

# Open it in browser
open index.html  # or just double-click it

🧩 Customize Your Toolbox

Edit the toolbox.json file to add new sections, tools, and commands.

{
  "Enumeration": {
    "nmap": [
      {
        "title": "Quick Scan",
        "command": "nmap -sC -sV <IP>"
      }
    ]
  }
}

🔁 Placeholders like <IP>, <PORT>, <LHOST> are automatically replaced with your input.
🧑‍💻 Contribute

PRs, issues, suggestions—all are welcome!
Let’s build the ultimate OSCP pentest toolbox together.

📬 Raise an Issue
📂 Submit a PR
📜 License

Released under the MIT License – use freely, share widely, learn deeply.
🙌 Credits

Created with 💻 and ☕ by Udit Chavda
Inspired by Liodeus OSCP Cheatsheet, HackTricks, and the offensive security community.


---

📌 **Next Steps**:  
To make this even better:

- Upload actual screenshots & GIFs to `/assets/screenshots/` in your repo.  
- Replace placeholder URLs in the markdown above with your hosted image links.  
- Consider adding a favicon/logo too!

Want help creating those GIFs or optimizing the screenshots? Just say the word.

