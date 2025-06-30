<<<<<<< Updated upstream
<<<<<<< Updated upstream
// This wrapper ensures our code doesn't run until the page is ready
document.addEventListener('DOMContentLoaded', function() {
    // --- CONFIGURATION ---
    const API_BASE_URL = 'https://phishfinder-backend.onrender.com'; // Production URL

    // --- Element References ---
    const toolContainer = document.querySelector('.phishfinder-tool');
    if (!toolContainer) {
        console.log('PhishFinder tool container not found on this page.');
        return; 
    }
    const checkButton = toolContainer.querySelector('#checkButton');
    const phishInput = toolContainer.querySelector('#phishInput');
    const resultContainer = toolContainer.querySelector('#result');
    const resultTemplate = toolContainer.querySelector('#result-template');
=======
=======
>>>>>>> Stashed changes
// This function will contain all our logic.
function phishFinderTool() {
    // --- CONFIGURATION ---
    const API_BASE_URL = 'https://phishfinder-backend.onrender.com';

    // --- Element References ---
    const checkButton = document.getElementById('checkButton');
    const phishInput = document.getElementById('phishInput');
    const resultContainer = document.getElementById('result');
    const resultTemplate = document.getElementById('result-template');
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes

    // --- State Variable ---
    let pollingIntervalId = null;

<<<<<<< Updated upstream
<<<<<<< Updated upstream
    // --- Event Listeners ---
    if(checkButton) {
        checkButton.addEventListener('click', startAnalysis);
    }

    // --- ASYNC WORKFLOW ---
    function startAnalysis() {
=======
=======
>>>>>>> Stashed changes
    // --- Main Click Handler using Event Delegation ---
    // This is the more robust method that avoids theme conflicts.
    document.body.addEventListener('click', function(event) {
        if (event.target && event.target.id === 'checkButton') {
            startAnalysis();
        }
    });

    function startAnalysis() {
        if (checkButton.disabled) return; // Prevent multiple clicks while processing

<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
        const inputValue = phishInput.value.trim();
        if (!inputValue) {
            alert('Please paste a link or email content first.');
            return;
        }
        
        setLoadingState();
        
        const apiUrl = `${API_BASE_URL}/api/check`;

        fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prompt: inputValue })
        })
<<<<<<< Updated upstream
<<<<<<< Updated upstream
        .then(response => {
            if (!response.ok) { 
                throw new Error(`Server responded with status: ${response.status}`);
            }
            return response.json();
        })
=======
        .then(response => response.json())
>>>>>>> Stashed changes
=======
        .then(response => response.json())
>>>>>>> Stashed changes
        .then(data => {
            if (data.status === 'pending' && data.task_id) {
                pollForResult(data.task_id);
            } else {
                throw new Error(data.error || 'Failed to start analysis task.');
            }
        })
        .catch(error => {
            console.error('Error starting analysis:', error);
            showErrorState('Could not start the analysis. The backend might be busy or down.');
        });
    }

    function pollForResult(taskId) {
<<<<<<< Updated upstream
<<<<<<< Updated upstream
        if (pollingIntervalId) {
            clearInterval(pollingIntervalId);
        }
=======
        if (pollingIntervalId) clearInterval(pollingIntervalId);
>>>>>>> Stashed changes
=======
        if (pollingIntervalId) clearInterval(pollingIntervalId);
>>>>>>> Stashed changes

        const resultUrl = `${API_BASE_URL}/api/result/${taskId}`;
        let attempts = 0;
        const maxAttempts = 20; // Poll for a maximum of 60 seconds

        pollingIntervalId = setInterval(() => {
            if (attempts >= maxAttempts) {
                clearInterval(pollingIntervalId);
                showErrorState("Analysis took too long to complete. Please try again later.");
                return;
            }
            
            fetch(resultUrl)
            .then(response => response.json())
            .then(data => {
                if (data.state === 'SUCCESS') {
                    clearInterval(pollingIntervalId);
                    populateResults(data.data.result);
                } else if (data.state === 'FAILURE') {
                    clearInterval(pollingIntervalId);
                    showErrorState('The analysis failed in the background.');
                }
            })
            .catch(error => {
                console.error('Error polling for results:', error);
                clearInterval(pollingIntervalId);
                showErrorState('Lost connection while checking for results.');
            });
            
            attempts++;
        }, 3000); 
    }

    // --- UI Update Functions ---
    function setLoadingState() {
        checkButton.disabled = true;
        checkButton.textContent = 'Analyzing...';
<<<<<<< Updated upstream
<<<<<<< Updated upstream
        resultContainer.innerHTML = `<div class="text-center p-8">
            <p class="pulsing font-semibold text-lg">Analyzing... this may take up to 20 seconds.</p>
            <p class="text-gray-600 mt-2">Your request has been submitted to our analysis engine.</p>
        </div>`;
=======
        resultContainer.innerHTML = `<div class="text-center p-8"><p class="pulsing font-semibold text-lg">Analyzing... this may take up to 20 seconds.</p><p class="text-gray-600 mt-2">Your request has been submitted to our analysis engine.</p></div>`;
>>>>>>> Stashed changes
=======
        resultContainer.innerHTML = `<div class="text-center p-8"><p class="pulsing font-semibold text-lg">Analyzing... this may take up to 20 seconds.</p><p class="text-gray-600 mt-2">Your request has been submitted to our analysis engine.</p></div>`;
>>>>>>> Stashed changes
    }

    function populateResults(data) {
        checkButton.disabled = false;
        checkButton.textContent = 'Check Risk';
        resultContainer.innerHTML = ''; 

        if (!data || !data.risk) {
<<<<<<< Updated upstream
<<<<<<< Updated upstream
            showErrorState("Received an incomplete or empty result from the server.");
=======
            showErrorState("Received an incomplete result from the server.");
>>>>>>> Stashed changes
=======
            showErrorState("Received an incomplete result from the server.");
>>>>>>> Stashed changes
            return;
        }

        const newResult = resultTemplate.content.cloneNode(true);
        const riskEl = newResult.querySelector('#risk');
        const summaryEl = newResult.querySelector('#summary');
        const domainAgeEl = newResult.querySelector('#domainAge');
        const mxRecordsEl = newResult.querySelector('#mxRecords');
        const watchForEl = newResult.querySelector('#watchFor');
        const adviceEl = newResult.querySelector('#advice');

        riskEl.textContent = `${data.risk.level} (${data.risk.score}/100)`;
        riskEl.className = `${data.risk.class} font-semibold`;
        summaryEl.textContent = data.summary || 'No summary available.';
        domainAgeEl.textContent = data.domainAge || 'N/A';
        mxRecordsEl.textContent = data.mxRecords || 'N/A';
        adviceEl.textContent = data.advice || 'No advice available.';
        
        if (data.watchFor && data.watchFor.length > 0) {
            watchForEl.innerHTML = data.watchFor.map(item => `<li>${item}</li>`).join('');
        } else {
            watchForEl.innerHTML = '<li>No specific indicators found.</li>';
        }

        resultContainer.appendChild(newResult);
    }
    
    function showErrorState(message) {
        checkButton.disabled = false;
        checkButton.textContent = 'Check Risk';
<<<<<<< Updated upstream
<<<<<<< Updated upstream
        resultContainer.innerHTML = `<div class="text-center p-8 border-2 border-red-300 bg-red-50 rounded-lg">
            <p class="font-bold text-red-700">Error</p>
            <p class="text-red-600 mt-2">${message}</p>
        </div>`;
    }
});
=======
=======
>>>>>>> Stashed changes
        resultContainer.innerHTML = `<div class="text-center p-8 border-2 border-red-300 bg-red-50 rounded-lg"><p class="font-bold text-red-700">Error</p><p class="text-red-600 mt-2">${message}</p></div>`;
    }
}

// This check ensures our script only runs if the tool is actually on the page.
if (document.querySelector('.phishfinder-tool')) {
    phishFinderTool();
<<<<<<< Updated upstream
}
>>>>>>> Stashed changes
=======
}
>>>>>>> Stashed changes
