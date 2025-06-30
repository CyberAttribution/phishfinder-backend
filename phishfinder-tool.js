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
    
    // --- STATE VARIABLE ---
    let pollingIntervalId = null; 

    // --- EVENT LISTENER ---
    // Using a single, delegated listener on the container for robustness
    toolContainer.addEventListener('click', function(event) {
        const target = event.target;
        if (target && target.id === 'checkButton') {
            startAnalysis();
        } else if (target && target.id === 'copyResultsButton') {
            copyFullResults();
        } else if (target && target.matches('.copy-btn')) {
            const targetId = target.dataset.copyTarget;
            const targetElement = toolContainer.querySelector(`#${targetId}`);
            if (targetElement) { copyToClipboard(targetElement.value, target); }
        }
        // Add your subscribe logic here if needed, for example:
        // else if (target && target.id === 'subscribeButton') { handleSubscription(); }
    });

    // --- MAIN ASYNC WORKFLOW with robust error handling ---
    async function startAnalysis() {
        if (checkButton.disabled) return;
        const inputValue = phishInput.value.trim();
        if (!inputValue) {
            alert('Please paste a link or email content first.');
            return;
        }
        
        setLoadingState();
        
        const apiUrl = `${API_BASE_URL}/api/check`;

        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ prompt: inputValue })
            });

            if (!response.ok) {
                // Catches HTTP errors like 500, 404, etc.
                throw new Error(`Server responded with status: ${response.status}`);
            }

            const data = await response.json();

            if (data.status === 'pending' && data.task_id) {
                pollForResult(data.task_id, inputValue);
            } else {
                // The server responded but didn't give us a task_id
                throw new Error(data.error || 'Failed to start analysis task.');
            }
        } catch (error) {
            // Catches network errors or errors thrown from the block above
            console.error('A critical error occurred in startAnalysis:', error);
            showErrorState('A critical error occurred. Could not send request to backend.');
        }
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
            .then(response => {
                if (!response.ok) throw new Error('Polling request failed.');
                return response.json();
            })
            .then(data => {
                if (data.state === 'SUCCESS') {
                    clearInterval(pollingIntervalId);
                    populateResults(data.data.result, rawInput);
                } else if (data.state === 'FAILURE') {
                    clearInterval(pollingIntervalId);
                    showErrorState('The analysis failed in the background.');
                }
                // If state is 'PENDING', do nothing and let the interval run again.
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
        const actionableContentEl = newResult.querySelector('#actionable-content');
        const securityAlertEl = newResult.querySelector('#securityAlert');
        const socialPostEl = newResult.querySelector('#socialPost');
        const resultActionsEl = newResult.querySelector('#result-actions');
        const virusTotalLinkEl = newResult.querySelector('#virusTotalLink');
        
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

        if (data.generated && data.generated.securityAlert) {
            actionableContentEl.classList.remove('hidden');
            securityAlertEl.value = data.generated.securityAlert;
            socialPostEl.value = data.generated.socialPost;
        }
        
        resultActionsEl.classList.remove('hidden');
        virusTotalLinkEl.href = `https://www.virustotal.com/gui/search/${encodeURIComponent(rawInput)}`;

        resultContainer.appendChild(newResult);
    }
    
    function showErrorState(message) {
        checkButton.disabled = false;
        checkButton.textContent = 'Check Risk';
        resultContainer.innerHTML = `<div class="text-center p-8 border-2 border-red-300 bg-red-50 rounded-lg"><p class="font-bold text-red-700">Error</p><p class="text-red-600 mt-2">${message}</p></div>`;
    }

    // --- ORIGINAL HELPER FUNCTIONS ---
    function copyToClipboard(text, button) {
        if (!navigator.clipboard) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-9999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                document.execCommand('copy');
                if(button) showCopiedMessage(button);
            } catch (err) { console.error('Fallback copy failed', err); }
            document.body.removeChild(textArea);
            return;
        }
        navigator.clipboard.writeText(text).then(() => {
            if(button) showCopiedMessage(button);
        });
    }

    function showCopiedMessage(button) {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        setTimeout(() => { button.textContent = originalText; }, 2000);
    }
    
    function copyFullResults() {
        const riskText = resultContainer.querySelector('#risk')?.textContent || 'N/A';
        const summaryText = resultContainer.querySelector('#summary')?.textContent || 'N/A';
        const domainAgeText = resultContainer.querySelector('#domainAge')?.textContent || 'N/A';
        const mxRecordsText = resultContainer.querySelector('#mxRecords')?.textContent || 'N/A';
        const adviceText = resultContainer.querySelector('#advice')?.textContent || 'N/A';
        const watchForItems = Array.from(resultContainer.querySelectorAll('#watchFor li')).map(li => `- ${li.textContent}`).join('\n');

        const fullReport = `Phishing Risk: ${riskText}\nSummary: ${summaryText}\nDomain Created: ${domainAgeText}\nMX Records Found: ${mxRecordsText}\nWhat to Watch For:\n${watchForItems}\nAdvice: ${adviceText}`.trim();
        copyToClipboard(fullReport, resultContainer.querySelector('#copyResultsButton'));
    }
});