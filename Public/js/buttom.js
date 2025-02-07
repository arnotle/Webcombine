function toggleText() {
    var extraText = document.querySelector('.extra-text');
    var button = document.querySelector('.btn');
    
    if (extraText.style.display === "none" || extraText.style.display === "") {
        extraText.style.display = "block";
        button.textContent = "แสดงน้อยลง";
    } else {
        extraText.style.display = "none";
        button.textContent = "เพิ่มเติม";
    }
}