function addQuestion() {
    const questionsDiv = document.getElementById('questions');
    const questionCount = questionsDiv.children.length + 1;

    const newQuestionDiv = document.createElement('div');
    newQuestionDiv.className = 'question';
    newQuestionDiv.innerHTML = `
        <h3>Question ${questionCount}</h3>
        <label>Question: <input type="text" name="question" required></label><br>
        <label>Choice A: <input type="text" name="choice_a" required></label><br>
        <label>Choice B: <input type="text" name="choice_b" required></label><br>
        <label>Choice C: <input type="text" name="choice_c" required></label><br>
        <label>Choice D: <input type="text" name="choice_d" required></label><br>
        <label>Answer:
            <select name="answer" required>
                <option value="A">A</option>
                <option value="B">B</option>
                <option value="C">C</option>
                <option value="D">D</option>
            </select>
        </label><br>
        <label>Explorer Points: <input type="number" name="explorerpoints" required></label><br>
        <hr>
    `;

    questionsDiv.appendChild(newQuestionDiv);
}

document.getElementById('create-module-form').addEventListener('submit', async function (event) {
    event.preventDefault();

    const form = event.target;
    const formData = new FormData(form);
    const moduleName = formData.get('module_name');

    const questions = [];
    document.querySelectorAll('.question').forEach((div) => {
        questions.push({
            question: div.querySelector('[name="question"]').value,
            choice_a: div.querySelector('[name="choice_a"]').value,
            choice_b: div.querySelector('[name="choice_b"]').value,
            choice_c: div.querySelector('[name="choice_c"]').value,
            choice_d: div.querySelector('[name="choice_d"]').value,
            answer: div.querySelector('[name="answer"]').value,
            explorerpoints: div.querySelector('[name="explorerpoints"]').value
        });
    });

    const payload = {
        module_name: moduleName,
        questions
    };

    try {
        const response = await fetch('/teacher/create_module', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            alert('Module and questions added successfully!');
        } else {
            const error = await response.json();
            alert(`Error: ${error.error}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
});