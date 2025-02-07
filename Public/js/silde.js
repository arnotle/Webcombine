// script.js
const carousel = document.querySelector('.carousel-inner');
let index = 0;

function showNextImage() {
  index++;
  if (index >= carousel.children.length) {
    index = 0;
  }
  carousel.style.transform = `translateX(${-index * 100}%)`;
}

setInterval(showNextImage, 3000);  // เลื่อนทุกๆ 3 วินาที
