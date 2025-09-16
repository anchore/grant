Output ".github/images/demo.gif"
Set Shell "zsh"

Require grant
Set Theme {
  "name": "anchore-next",
  "black": "#2A2A3A",
  "red": "#DA36AC",
  "green": "#50DD43",
  "yellow": "#F5D66D",
  "blue": "#498DFF",
  "magenta": "#DA36AC",
  "cyan": "#43C1BE",
  "white": "#E6E6F0",

  "brightBlack": "#3D3C58",
  "brightRed": "#F05EC4",
  "brightGreen": "#6FF75F",
  "brightYellow": "#FFE58F",
  "brightBlue": "#6FAFFF",
  "brightMagenta": "#E46BC0",
  "brightCyan": "#65E5E0",
  "brightWhite": "#FFFFFF",

  "background": "#1E1D2B",
  "foreground": "#D0CCE8",
  "selection": "#383756",
  "cursor": "#D0CCE8"
}
#Set FontFamily "Iosevka Term"
Set FontSize 22
Set Width 1080
Set Height 1080
Set Padding 2
Set WindowBar Rings
#Set Theme TokyoNightStorm
#Set LineHeight 1
Set Margin 16
#Set MarginFill "#0f40c0"
Set MarginFill "#dd4814"
Set BorderRadius 8
Set Framerate 60
Set PlaybackSpeed 1.0
Set TypingSpeed 0.02
Env PS1 "[0;38;5;231;48;5;31;1m anchore [0;38;5;31;48;5;240;22m [0;38;5;252;48;5;240;1m~ [0;38;5;240;49;22m [0m"
Sleep 150ms

Type `grant list alpine:latest`
Enter
Sleep 5s

Type `grant list alpine:latest GPL-2.0-only`
Enter
Sleep 5s

Type `grant list alpine:latest GPL-2.0-only --pkg apk-tools`
Enter
Sleep 5s
