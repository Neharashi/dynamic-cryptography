import streamlit as st
import textwrap

def render_pipeline_css():
    st.markdown("""
    <style>
        /* MAIN THEME */
        .main { background-color: #0b0f19; }
        h1, h2, h3 { color: #f8fafc; font-family: 'Segoe UI', sans-serif; letter-spacing: 0.5px; }
        
        /* 1. INTRO BOX STYLING (VERTICAL) */
        .intro-container {
            background: linear-gradient(145deg, #1e293b, #0f172a);
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 20px 25px;
            margin-bottom: 25px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.3);
        }
        .intro-section { margin-bottom: 0; }
        .intro-divider-h { height: 1px; background: linear-gradient(90deg, transparent, #475569, transparent); margin: 15px 0; }
        .intro-title { color: #60a5fa; font-size: 1.15em; font-weight: 700; margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }
        .intro-text { color: #cbd5e1; font-size: 1.0em; line-height: 1.5; font-weight: 400; }

        /* 2. FLOWCHART STYLING */
        .flow-step-container {
            position: relative;
            padding-left: 35px;
            padding-bottom: 25px;
            animation: fadeIn 0.5s ease-out;
        }
        .flow-step-container::before {
            content: ''; position: absolute; left: 12px; top: 15px; bottom: -5px; 
            width: 2px; background: #334155; z-index: 0;
        }
        
        /* CARD HEADER */
        .flow-card-header {
            background: #151e2e;
            padding: 12px 15px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            border: 1px solid #334155;
            border-bottom: none; 
            transition: all 0.3s ease;
        }
        .flow-card-header:hover { background: #1e293b; box-shadow: 0 0 15px rgba(59, 130, 246, 0.1); }

        /* CARD MATH */
        .flow-card-math {
            background: #020617;
            border: 1px solid #334155;
            border-top: 1px solid #1e293b; 
            padding: 15px;
            text-align: center;
        }
        
        /* CARD OUTPUT PREVIEW (New) */
        .flow-card-output {
            background: #0f172a;
            border: 1px solid #334155;
            border-top: none;
            border-bottom-left-radius: 8px;
            border-bottom-right-radius: 8px;
            padding: 8px 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            color: #10b981; /* Matrix Green text */
            text-align: right;
        }

        .rounded-bottom { border-bottom-left-radius: 8px; border-bottom-right-radius: 8px; border-bottom: 1px solid #334155; }

        /* INDICATORS */
        .dot-blue { position: absolute; left: 5px; top: 15px; width: 16px; height: 16px; background: #3b82f6; border: 3px solid #0b0f19; border-radius: 50%; z-index: 1; }
        .dot-green { position: absolute; left: 5px; top: 15px; width: 16px; height: 16px; background: #10b981; border: 3px solid #0b0f19; border-radius: 50%; z-index: 1; }
        .border-blue { border-left: 4px solid #3b82f6; }
        .border-green { border-left: 4px solid #10b981; }

        .node-title { font-weight: 700; color: #e2e8f0; font-size: 1.05em; margin-bottom: 4px; }
        .node-desc { color: #94a3b8; font-size: 0.95em; line-height: 1.4; }

        /* DEFINITION BOXES */
        .def-box { 
            background: linear-gradient(90deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0) 100%);
            border-left: 3px solid #64748b; 
            padding: 12px; 
            border-radius: 4px; 
        }
        .def-label { color: #94a3b8; font-weight: 700; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }
        .def-text { color: #e2e8f0; font-size: 1.0em; margin-top: 2px; }
        
        @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
    </style>
    """, unsafe_allow_html=True)

def render_clean_definition(title, desc):
    st.markdown(f"""
    <div class="def-box">
        <div class="def-label">{title}</div>
        <div class="def-text">{desc}</div>
    </div>
    """, unsafe_allow_html=True)

def render_flow_step(container, data, theme="blue"):
    with container:
        has_math = bool(data.get("math_html"))
        has_output = bool(data.get("output_preview"))
        
        border_class = "border-blue" if theme == "blue" else "border-green"
        dot_class = "dot-blue" if theme == "blue" else "dot-green"
        
        # Logic for rounding corners: Only round if no math AND no output follow
        header_radius = "rounded-bottom" if (not has_math and not has_output) else ""
        
        st.markdown(f'<div class="flow-step-container"><div class="{dot_class}"></div>', unsafe_allow_html=True)
        
        # 1. TEXT HEADER
        html_text = f"""
        <div class="flow-card-header {border_class} {header_radius}">
            <div class="node-title">{data['title']}</div>
            <div class="node-desc">{data['explanation']}</div>
        </div>
        """
        st.markdown(html_text, unsafe_allow_html=True)
        
        # 2. MATH BODY
        if has_math:
            math_radius = "rounded-bottom" if not has_output else ""
            # Apply specific styling if output follows
            st.markdown(f'<div class="flow-card-math {border_class} {math_radius}">', unsafe_allow_html=True)
            st.latex(data['math_html'])
            st.markdown('</div>', unsafe_allow_html=True)

        # 3. OUTPUT PREVIEW (New)
        if has_output:
            st.markdown(f"""
            <div class="flow-card-output {border_class}">
                {data['output_preview']}
            </div>
            """, unsafe_allow_html=True)
            
        st.markdown('</div>', unsafe_allow_html=True)