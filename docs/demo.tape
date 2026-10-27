# Renders docs/demo.gif with https://github.com/charmbracelet/vhs
#   docker compose up --build -d        (wait ~40 s for Keycloak)
#   vhs docs/demo.tape
Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 900
Set Padding 20
Set TypingSpeed 40ms

Type "uv run python scripts/demo.py"
Enter
Sleep 25s
