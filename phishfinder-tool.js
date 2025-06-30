// This wrapper ensures all our code is contained and runs after the page is ready.
document.addEventListener('DOMContentLoaded', function() {
    // --- CONFIGURATION ---
    const API_BASE_URL = 'https://phishfinder-backend.onrender.com';

    // --- ELEMENT REFERENCES ---
    const toolContainer = document.querySelector('.phishfinder-tool');
    if (!toolContainer) {
        console.error('PhishFinder tool container not found. Script will not run.');
        return;
    }
    const checkButton = document.getElementById('checkButton');
    const phishInput = document.getElementById('phishInput');
    const resultContainer = document.getElementById('result');
    const resultTemplate = document.getElementById('result-template');
    const actionableContent = toolContainer.querySelector('#actionable-content');
    const securityAlertEl = toolContainer.querySelector('#securityAlert');
    const socialPostEl = toolContainer.querySelector('#socialPost');
    const resultActions = toolContainer.querySelector('#result-actions');
    const copyResultsButton = toolContainer.querySelector('#copyResultsButton');
    const virusTotalLink = toolContainer.querySelector('#virusTotalLink');
    const copyButtons = toolContainer.querySelectorAll('.copy-btn');
    const emailInput = document.getElementById('emailInput');
    const subscribeButton = document.getElementById('subscribeButton');

    // --- STATE VARIABLE ---
    let pollingIntervalId = null; 

    // --- EVENT LISTENERS ---
    checkButton.addEventListener('click', startAnalysis);

    copyButtons.forEach(button => {
        button.addEventListener('click', (e) => {
            const targetId = e.currentTarget.dataset.copyTarget;
            const targetElement = toolContainer.querySelector(`#${targetId}`);
            if (targetElement) { copyToClipboard(targetElement.value, e.currentTarget); }
        });
    });

    copyResultsButton.addEventListener('click', (e) => {
        const riskEl = resultContainer.querySelector('#risk');
        const summaryEl = resultContainer.querySelector('#summary');
        const domainAgeEl = resultContainer.querySelector('#domainAge');
        const mxRecordsEl = resultContainer.querySelector('#mxRecords');
        const watchForEl = resultContainer.querySelector('#watchFor');
        const adviceEl = resultContainer.querySelector('#advice');

        const fullReport = `
Phishing Risk: ${riskEl ? riskEl.textContent : 'N/A'}
Summary: ${summaryEl ? summaryEl.textContent : 'N/A'}
Domain Created: ${domainAgeEl ? domainAgeEl.textContent : 'N/A'}
MX Records Found: ${mxRecordsEl ? mxRecordsEl.textContent : 'N/A'}
What to Watch For:
${watchForEl ? Array.from(watchForEl.querySelectorAll('li')).map(li => `- ${li.textContent}`).join('\n') : 'N/A'}
Advice: ${adviceEl ? adviceEl.textContent : 'N/A'}`.trim();
        copyToClipboard(fullReport, e.currentTarget);
    });
    
    // You can add your subscribe button logic here if it's not handled elsewhere
    // subscribeButton.addEventListener('click', () => { ... });


    // --- ASYNC WORKFLOW ---
    function startAnalysis() {
        const inputValue = phishInput.value.trim();
        if (!inputValue) {
            alert('Please paste a link or email content first.');
            return;
        }
        
        setLoadingState(inputValue);
        
        const apiUrl = `${API_BASE_URL}/api/check`;

        fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prompt: inputValue })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'pending' && data.task_id) {
                pollForResult(data.task_id, inputValue);
            } else {
                throw new Error(data.error || 'Failed to start analysis task.');
            }
        })
        .catch(error => {
            console.error('Error starting analysis:', error);
            showErrorState('Could not start the analysis. The backend might be busy or down.');
        });
    }

    function pollForResult(taskId, rawInput) {
        if (pollingIntervalId) clearInterval(pollingIntervalId);

        const resultUrl = `${API_BASE_URL}/api/result/${taskId}`;
        let attempts = 0;
        const maxAttempts = 20;

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
                    // Pass rawInput along to the final results display
                    populateResults(data.data.result, rawInput);
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

    // --- UI UPDATE FUNCTIONS ---
    function setLoadingState() {
        checkButton.disabled = true;
        checkButton.textContent = 'Analyzing...';
        resultContainer.innerHTML = `<div class="text-center p-8"><p class="pulsing font-semibold text-lg">Analyzing... this may take up to 20 seconds.</p><p class="text-gray-600 mt-2">Your request has been submitted to our analysis engine.</p></div>`;
        actionableContent.classList.add('hidden');
        resultActions.classList.add('hidden');
    }

    function populateResults(data, rawInput) {
        checkButton.disabled = false;
        checkButton.textContent = 'Check Risk';
        resultContainer.innerHTML = ''; 

        if (!data || !data.risk) {
            showErrorState("Received an incomplete result from the server.");
            return;
        }

        const newResult = resultTemplate.content.cloneNode(true);
        const riskEl = newResult.querySelector('#risk');
        const summaryEl = newResult.querySelector('#summary');
        const domainAgeEl = newResult.querySelector('#domainAge');
        const mxRecordsEl = newResult.querySelector('#mxRecords');
        const watchForEl = newResult.querySelector('#watchFor');
        const adviceEl = newResult.querySelector('#advice');
        
        // Populate main results
        riskEl.textContent = `${data.risk.level} (${data.risk.score}/100)`;
        riskEl.className = `${data.risk.class} font-semibold`;
        summaryEl.textContent = data.summary || 'N/A';
        domainAgeEl.textContent = data.domainAge || 'N/A';
        mxRecordsEl.textContent = data.mxRecords || 'N/A';
        adviceEl.textContent = data.advice || 'N/A';
        
        if (data.watchFor && data.watchFor.length > 0) {
            watchForEl.innerHTML = data.watchFor.map(item => `<li>${item}</li>`).join('');
        } else {
            watchForEl.innerHTML = '<li>No specific indicators found.</li>';
        }

        resultContainer.appendChild(newResult);

        // Show actionable content if it exists in the response
        if (data.generated && data.generated.securityAlert) {
            securityAlertEl.value = data.generated.securityAlert;
            socialPostEl.value = data.generated.socialPost;
            actionableContent.classList.remove('hidden');
        }

        // Always show the result actions block after a successful analysis
        resultActions.classList.remove('hidden');
        virusTotalLink.href = `https://www.virustotal.com/gui/search/${encodeURIComponent(rawInput)}`;
    }
    
    function showErrorState(message) {
        checkButton.disabled = false;
        checkButton.textContent = 'Check Risk';
        resultContainer.innerHTML = `<div class="text-center p-8 border-2 border-red-300 bg-red-50 rounded-lg"><p class="font-bold text-red-700">Error</p><p class="text-red-600 mt-2">${message}</p></div>`;
    }

    // --- ORIGINAL HELPER FUNCTIONS ---
    function copyToClipboard(text, button) {
        if (!navigator.clipboard) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-9999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                document.execCommand('copy');
                showCopiedMessage(button);
            } catch (err) {
                console.error('Fallback copy failed', err);
            }
            document.body.removeChild(textArea);
            return;
        }
        navigator.clipboard.writeText(text).then(() => {
            showCopiedMessage(button);
        });
    }

    function showCopiedMessage(button) {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        setTimeout(() => { button.textContent = originalText; }, 2000);
    }
});