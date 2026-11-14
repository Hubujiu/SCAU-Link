/* Keep each desktop artboard intact while fitting its overview tile. */
document.querySelectorAll('[data-icon]').forEach(element=>{
  element.innerHTML=(window.UI_ICONS[element.dataset.icon]||'').replace(/<svg\b/,'<svg class="icon" aria-hidden="true"');
});
const observer=new ResizeObserver(entries=>{
  entries.forEach(({target,contentRect})=>{
    const mini=target.classList.contains('mini-screen-frame');
    const scale=contentRect.width/(mini?400:1060);
    const frame=target.querySelector('iframe');
    frame.style.transform=`scale(${scale})`;
    target.style.height=`${(mini?650:730)*scale}px`;
  });
});
document.querySelectorAll('.screen-frame, .mini-screen-frame').forEach(frame=>observer.observe(frame));
