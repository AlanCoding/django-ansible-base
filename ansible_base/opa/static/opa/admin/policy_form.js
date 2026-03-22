(function() {
    'use strict';

    // Cache for registry data
    let registryData = null;

    function fetchRegistry() {
        if (registryData) {
            return Promise.resolve(registryData);
        }
        return fetch('/admin/dab_opa/api/registry/')
            .then(r => r.json())
            .then(data => {
                registryData = data.resources;
                return registryData;
            });
    }

    function fetchObjects(resource, field, search) {
        const params = new URLSearchParams({resource, field, q: search || ''});
        return fetch('/admin/dab_opa/api/object_lookup/?' + params)
            .then(r => r.json())
            .then(data => data.objects);
    }

    // Filter a select element to only show options in allowedValues
    function filterSelect(selectEl, allowedValues, currentValue) {
        const options = selectEl.querySelectorAll('option');
        options.forEach(opt => {
            if (opt.value === '') return; // keep the blank option
            opt.style.display = allowedValues.includes(opt.value) ? '' : 'none';
        });
        // If current value is not in allowed, reset to blank
        if (currentValue && !allowedValues.includes(currentValue)) {
            selectEl.value = '';
        }
    }

    function setupPolicyForm(prefix) {
        // Find the resource, action, and field_name selects
        // They might be named like "id_resource" or "id_policies-0-resource" for inlines
        const resourceSel = document.getElementById(prefix + 'resource');
        const actionSel = document.getElementById(prefix + 'action');
        const fieldSel = document.getElementById(prefix + 'field_name');
        const valueSel = document.getElementById(prefix + 'constant_value');
        const valueTypeEl = document.getElementById(prefix + 'value_type');

        if (!resourceSel) return;

        function updateDependents() {
            fetchRegistry().then(resources => {
                const resource = resourceSel.value;
                if (!resource || !resources[resource]) {
                    return;
                }
                const info = resources[resource];

                // Filter actions
                if (actionSel) {
                    filterSelect(actionSel, info.actions, actionSel.value);
                }

                // Filter fields
                if (fieldSel) {
                    filterSelect(fieldSel, info.fields, fieldSel.value);
                }
            });
        }

        // Add object picker button next to constant_value
        if (valueSel && !document.getElementById(prefix + 'object_picker_btn')) {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.id = prefix + 'object_picker_btn';
            btn.textContent = 'Browse...';
            btn.style.marginLeft = '8px';
            btn.style.cursor = 'pointer';
            btn.onclick = function() {
                showObjectPicker(resourceSel, fieldSel, valueSel);
            };
            valueSel.parentNode.insertBefore(btn, valueSel.nextSibling);
        }

        resourceSel.addEventListener('change', updateDependents);
        // Run once on load
        updateDependents();
    }

    function showObjectPicker(resourceSel, fieldSel, valueSel) {
        const resource = resourceSel ? resourceSel.value : '';
        const field = fieldSel ? fieldSel.value : '';
        if (!resource || !field) {
            alert('Select a resource and field first.');
            return;
        }

        fetchObjects(resource, field, '').then(objects => {
            if (objects.length === 0) {
                alert('No objects found for ' + resource + '.' + field);
                return;
            }

            // Build a simple modal
            const overlay = document.createElement('div');
            overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:10000;display:flex;align-items:center;justify-content:center;';

            const modal = document.createElement('div');
            modal.style.cssText = 'background:white;padding:20px;border-radius:8px;max-height:80vh;overflow-y:auto;min-width:400px;';

            const title = document.createElement('h3');
            title.textContent = 'Select ' + field + ' for ' + resource;
            title.style.marginTop = '0';
            modal.appendChild(title);

            // Search input
            const searchInput = document.createElement('input');
            searchInput.type = 'text';
            searchInput.placeholder = 'Search...';
            searchInput.style.cssText = 'width:100%;padding:6px;margin-bottom:10px;box-sizing:border-box;';
            modal.appendChild(searchInput);

            const list = document.createElement('div');
            modal.appendChild(list);

            function renderObjects(objs) {
                list.innerHTML = '';
                objs.forEach(obj => {
                    const item = document.createElement('div');
                    item.style.cssText = 'padding:6px 8px;cursor:pointer;border-bottom:1px solid #eee;';
                    item.textContent = obj.label;
                    item.onmouseover = function() { this.style.background = '#e8f0fe'; };
                    item.onmouseout = function() { this.style.background = ''; };
                    item.onclick = function() {
                        valueSel.value = obj.id;
                        overlay.remove();
                    };
                    list.appendChild(item);
                });
                if (objs.length === 0) {
                    list.innerHTML = '<p style="color:#666">No results.</p>';
                }
            }

            renderObjects(objects);

            let searchTimeout;
            searchInput.addEventListener('input', function() {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(function() {
                    fetchObjects(resource, field, searchInput.value).then(renderObjects);
                }, 300);
            });

            // Close button
            const closeBtn = document.createElement('button');
            closeBtn.textContent = 'Cancel';
            closeBtn.style.cssText = 'margin-top:10px;padding:6px 16px;cursor:pointer;';
            closeBtn.onclick = function() { overlay.remove(); };
            modal.appendChild(closeBtn);

            overlay.appendChild(modal);
            overlay.onclick = function(e) {
                if (e.target === overlay) overlay.remove();
            };
            document.body.appendChild(overlay);
            searchInput.focus();
        });
    }

    // Initialize when the DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        // Standalone policy form
        setupPolicyForm('id_');

        // Inline policy forms (for Role admin)
        // Django inline formsets use ids like: id_policies-0-resource
        const inlineRows = document.querySelectorAll('.dynamic-policies');
        inlineRows.forEach(function(row) {
            const inputs = row.querySelectorAll('select[id*="-resource"]');
            inputs.forEach(function(input) {
                const match = input.id.match(/^(id_policies-\d+-)/);
                if (match) {
                    setupPolicyForm(match[1]);
                }
            });
        });

        // Handle dynamically added inline rows
        if (typeof django !== 'undefined' && django.jQuery) {
            django.jQuery(document).on('formset:added', function(event, $row, formsetName) {
                if (formsetName === 'policies') {
                    const selects = $row[0].querySelectorAll('select[id*="-resource"]');
                    selects.forEach(function(sel) {
                        const match = sel.id.match(/^(id_policies-\d+-)/);
                        if (match) {
                            setupPolicyForm(match[1]);
                        }
                    });
                }
            });
        }
    });
})();
