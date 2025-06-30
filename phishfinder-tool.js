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
    
    // We will get references to the result-actions and subscribe buttons later, inside event handlers.

    // --- STATE VARIABLE ---
    let pollingIntervalId = null; 

    // --- EVENT LISTENER ---
    // Use event delegation on the main container for robustness
    toolContainer.addEventListener('click', function(event) {
        if (event.target && event.target.id === 'checkButton') {
            startAnalysis();
        }

        if (event.target && event.target.id === 'copyResultsButton') {
            copyFullResults();
        }

        if (event.target && event.target.matches('.copy-btn')) {
            const targetId = event.target.dataset.copyTarget;
            const targetElement = toolContainer.querySelector(`#${targetId}`);
            if (targetElement) { copyToClipboard(targetElement.value, event.target); }
        }
        
        // Add subscribe button logic here if needed
        // if (event.target && event.target.id === 'subscribeButton') { ... }
    });


    // --- MAIN ASYNC WORKFLOW ---
    function startAnalysis() {
        if (checkButton.disabled) return;
        const inputValue = phishInput.value.trim();
        if (!inputValue) {
            alert('Please paste a link or email content first.');
            return;
        }
        setLoadingState();
        fetch(`${API_BASE_URL}/api/check`, {
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
    }

    function populateResults(data, rawInput) {
        checkButton.disabled = false;
        checkButton.textContent = 'Check Risk';
        resultContainer.innerHTML = '';

        if (!data || !data.risk) {
            showErrorState("Received an incomplete result from the server.");
            return;
        }

        // The HTML structure is now self-contained here, preventing conflicts.
        resultContainer.innerHTML = `
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-4">
                <div><p><strong>Phishing Risk:</strong> <span id="risk" class="font-semibold"></span></p></div>
                <div><p><strong>Domain Created:</strong> <span id="domainAge"></span></p></div>
                <div><p><strong>MX Records Found:</strong> <span id="mxRecords"></span></p></div>
            </div>
            <div class="mt-4"><p><strong>Summary:</strong> <span id="summary"></span></p></div>
            <div class="mt-4"><p><strong>What to Watch For:</strong></p><ul id="watchFor" class="list-disc list-inside space-y-1 mt-2 text-gray-700"></ul></div>
            <div class="mt-4"><p><strong>Advice:</strong> <span id="advice"></span></p></div>
            <div id="actionable-content" class="mt-6 pt-6 border-t hidden">
                <h3 class="text-lg font-semibold mb-4 text-gray-800">Generated Content</h3>
                <div class="space-y-4">
                    <div>
                        <label for="securityAlert" class="block text-sm font-medium text-gray-700">Internal Security Alert:</label>
                        <textarea id="securityAlert" rows="4" readonly class="w-full mt-1 p-2 border border-gray-300 rounded-md bg-white/70"></textarea>
                        <button data-copy-target="securityAlert" class="copy-btn mt-2 px-3 py-1 text-sm font-medium text-white bg-gray-600 rounded-md hover:bg-gray-700">Copy Alert</button>
                    </div>
                    <div>
                        <label for="socialPost" class="block text-sm font-medium text-gray-700">Social Media Post:</label>
                        <textarea id="socialPost" rows="3" readonly class="w-full mt-1 p-2 border border-gray-300 rounded-md bg-white/70"></textarea>
                        <button data-copy-target="socialPost" class="copy-btn mt-2 px-3 py-1 text-sm font-medium text-white bg-gray-600 rounded-md hover:bg-gray-700">Copy Post</button>
                    </div>
                </div>
            </div>
            <div id="result-actions" class="mt-6 pt-4 border-t flex flex-col sm:flex-row items-center justify-between gap-4">
                <button id="copyResultsButton" class="w-full sm:w-auto px-4 py-2 text-base font-semibold text-white bg-green-600 rounded-lg hover:bg-green-700">Copy Full Results</button>
                <a href="#" id="virusTotalLink" target="_blank" class="w-full sm:w-auto text-center px-4 py-2 text-base font-semibold text-white bg-gray-700 rounded-lg hover:bg-gray-800">Check on VirusTotal</a>
            </div>
        `;

        // Populate the newly created elements
        const riskEl = document.getElementById('risk');
        const summaryEl = document.getElementById('summary');
        const domainAgeEl = document.getElementById('domainAge');
        const mxRecordsEl = document.getElementById('mxRecords');
        const watchForEl = document.getElementById('watchFor');
        const adviceEl = document.getElementById('advice');
        const actionableContentEl = document.getElementById('actionable-content');
        const securityAlertEl_disp = document.getElementById('securityAlert');
        const socialPostEl_disp = document.getElementById('socialPost');
        const virusTotalLinkEl = document.getElementById('virusTotalLink');

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
            securityAlertEl_disp.value = data.generated.securityAlert;
            socialPostEl_disp.value = data.generated.socialPost;
            actionableContentEl.classList.remove('hidden');
        }
        
        virusTotalLinkEl.href = `https://www.virustotal.com/gui/search/${encodeURIComponent(rawInput)}`;
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
            } catch (err) {
                console.error('Fallback copy failed', err);
            }
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
        const riskText = document.getElementById('risk')?.textContent || 'N/A';
        const summaryText = document.getElementById('summary')?.textContent || 'N/A';
        const domainAgeText = document.getElementById('domainAge')?.textContent || 'N/A';
        const mxRecordsText = document.getElementById('mxRecords')?.textContent || 'N/A';
        const adviceText = document.getElementById('advice')?.textContent || 'N/A';
        const watchForItems = Array.from(document.querySelectorAll('#watchFor li')).map(li => `- ${li.textContent}`).join('\n');

        const fullReport = `
Phishing Risk: ${riskText}
Summary: ${summaryText}
Domain Created: ${domainAgeText}
MX Records Found: ${mxRecordsText}
What to Watch For:
${watchForItems}
Advice: ${adviceText}`.trim();

        copyToClipboard(fullReport, document.getElementById('copyResultsButton'));
    }
});