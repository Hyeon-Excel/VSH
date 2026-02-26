export function renderUserInput(input: string): void {
  const target = document.getElementById("target");
  if (!target) {
    return;
  }
  target.innerHTML = input;
}
