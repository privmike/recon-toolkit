import json
from utils.logger import log

def parse_data(data):

    if isinstance(data, dict): # klo data berupa dictionary
        if not data:
            return "<span class='text-gray-500'>Empty</span>"

        html = '<table class="w-full text-sm text-left border-collapse mt-2 mb-4">\n<tbody>\n'
        for key, value in data.items():
            html += f'''
            <tr class="border-b border-gray-200 last:border-0 hover:bg-gray-50">
                <td class="py-2 px-4 bg-gray-100 font-semibold text-gray-700 w-1/4 align-top border-r border-gray-200">{key}</td>
                <td class="py-2 px-4 text-gray-800 align-top break-words">{parse_data(value)}</td>
            </tr>
            '''
        html += '</tbody>\n</table>'
        return html

    elif isinstance(data, list): #lek datane berupa list/array
        if not data:
            return "<span class='text-gray-500'>Empty</span>"


        if all(isinstance(item, dict) for item in data): #cek apakah semua entry di dalam var data itu sebuah dictionary
            headers = []
            #ngambil keys dari tial dictioanry entry yang ada di list
            for item in data:
                for k in item.keys():
                    if k not in headers:
                        headers.append(k)

            html = '<div class="overflow-x-auto mt-2 mb-4 border border-gray-200 rounded-lg"><table class="w-full text-sm text-left border-collapse">\n'
            html += '<thead  class="bg-blue-50 text-blue-800 border-b-2 border-blue-200">\n<tr>\n'
            for h in headers:
                html += f'<th class="py-2 px-4 font-semibold whitespace-nowrap">{h}</th>\n'
            html += '</tr>\n</thead>\n<tbody>\n'

            for item in data:
                html += '<tr class="border-b border-gray-200 last:border-0 hover:bg-gray-50">\n'
                for h in headers:
                    val = item.get(h,'')
                    html += f'<td class="py-2 px-4 text-gray-800 align-top">{parse_data(val)}</td>\n'
                html += '</tr>\n'
            html += '</tbody>\n</table></div>\n'
            return html
        else:
            html = '<ul class="list-disc list-inside text-sm text-gray-800 space-y-1">\n'
            for item in data:
                html += f'<li>{parse_data(item)}</li>\n'
            html += '</ul>\n'
            return html
    else: #data prmitif spr string ,int, nul, bool, dkk , ini base casenya
        if data is None:
            return "<span class='text-gray-400 italic font-mono'>null</span>"
        return str(data).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;') #sanitasi agar tidak menjalankan perintah html (xss)


def generate_html_final_report(json_file, html_output_path):

    with open(json_file,'r', encoding='utf-8') as file:
        report_data = json.load(file)


    target = report_data.get('target','unknown target domain')
    start_time = report_data.get('start_time','unknown start time')
    results = report_data.get('results',{})

    #sampekno iki html e inget mari
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report - {target}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        table table {{ margin-top: 0.5rem !important; margin-bottom: 0.5rem !important; }}
    </style>
</head>
<body class="bg-gray-100 font-sans p-4 md:p-8">
    <div class="max-w-7xl mx-auto bg-white shadow-md rounded-xl overflow-hidden border border-gray-200">
        
        <div class="bg-slate-800 text-white px-8 py-6 border-b-4 border-blue-500">
            <h1 class="text-3xl font-bold tracking-tight">Reconnaissance Report</h1>
            <div class="mt-2 text-slate-300 flex flex-col md:flex-row md:gap-6 text-sm font-mono">
                <p>Target: <span class="font-semibold text-white">{target}</span></p>
                <p>Start Time: <span class="font-semibold text-white">{start_time}</span></p>
            </div>
        </div>
        
        <div class="p-8">
"""
    if not results:
        html_content += "<p class='text-gray-500 italic text-center py-10'>No scan results found.</p>"
    else:
        for module_name, module_data in results.items():
            html_content += f"""
            <div class="mb-10 border border-gray-200 rounded-lg shadow-sm overflow-hidden bg-white">
                <div class="bg-slate-50 px-6 py-4 border-b border-gray-200">
                    <h2 class="text-xl font-bold text-slate-800 flex items-center gap-2">
                        <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                        {module_name.replace('_', ' ')}
                    </h2>
                </div>
                <div class="p-6 overflow-x-auto">
            """

            if isinstance(module_data, dict): # untuk entry tiap toool yang ad
                for tool_name, tool_data in module_data.items():
                    html_content += f"""
                    <div class="mb-8 last:mb-0">
                        <h3 class="text-md font-bold text-blue-700 mb-3 border-b-2 border-blue-100 inline-block pb-1">{tool_name}</h3>
                        {parse_data(tool_data)}
                    </div>
                    """
            else:
                html_content += parse_data(module_data)

            html_content += """
                </div>
            </div>
            """
    html_content += """
        </div>
        
        <div class="bg-slate-50 text-center py-4 border-t border-gray-200 text-sm text-slate-500">
            ---End Of Report---
        </div>
    </div>
</body>
</html>
"""
    with open(html_output_path, 'w', encoding='utf-8') as file:
        file.write(html_content)
    log.info(f"HTML report generated successfully: {html_output_path}")


