//Copyright (C) Microsoft Corporation.  All rights reserved.

using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;

// See the ReadMe.html for additional information
public class ObjectDumper
{

    public static void Write(object element)
    {
        Write(element, 0);
    }

    public static void Write(object element, int depth)
    {
        Write(element, depth, Console.Out);
    }

    public static void Write(object element, int depth, TextWriter log)
    {
        ObjectDumper dumper = new ObjectDumper(depth);
        dumper.writer = log;
        dumper.WriteObject(null, element);
    }

    TextWriter writer;
    int pos;
    int level;
    int depth;

    private ObjectDumper(int depth)
    {
        this.depth = depth;
    }

    private void Write(string s)
    {
        if (s != null)
        {
            writer.Write(s);
            pos += s.Length;
        }
    }

    private void WriteIndent()
    {
        for (int i = 0; i < level; i++) writer.Write("  ");
    }

    private void WriteLine()
    {
        writer.WriteLine();
        pos = 0;
    }

    private void WriteTab()
    {
        Write("  ");
        while (pos % 8 != 0) Write(" ");
    }

    private void WriteObject(string prefix, object element)
    {
        if (element == null || element is ValueType || element is string)
        {
            WriteIndent();
            Write(prefix);
            WriteValue(element);
            WriteLine();
        }
        else
        {
            IEnumerable enumerableElement = element as IEnumerable;
            if (enumerableElement != null)
            {
                foreach (object item in enumerableElement)
                {
                    if (item is IEnumerable && !(item is string))
                    {
                        WriteIndent();
                        Write(prefix);
                        Write("...");
                        WriteLine();
                        if (level < depth)
                        {
                            level++;
                            WriteObject(prefix, item);
                            level--;
                        }
                    }
                    else
                    {
                        WriteObject(prefix, item);
                    }
                }
            }
            else
            {
                MemberInfo[] members = element.GetType().GetMembers(BindingFlags.Public | BindingFlags.Instance);
                WriteIndent();
                Write(prefix);
                bool propWritten = false;
                foreach (MemberInfo m in members)
                {
                    FieldInfo f = m as FieldInfo;
                    PropertyInfo p = m as PropertyInfo;
                    if (f != null || p != null)
                    {
                        if (propWritten)
                        {
                            WriteTab();
                        }
                        else
                        {
                            propWritten = true;
                        }
                        Write(m.Name);
                        Write("=");
                        Type t = f != null ? f.FieldType : p.PropertyType;
                        if (t.IsValueType || t == typeof(string))
                        {
                            WriteValue(f != null ? f.GetValue(element) : p.GetValue(element, null));
                        }
                        else
                        {
                            if (typeof(IEnumerable).IsAssignableFrom(t))
                            {
                                Write("...");
                            }
                            else
                            {
                                Write("{ }");
                            }
                        }
                    }
                }
                if (propWritten) WriteLine();
                if (level < depth)
                {
                    foreach (MemberInfo m in members)
                    {
                        FieldInfo f = m as FieldInfo;
                        PropertyInfo p = m as PropertyInfo;
                        if (f != null || p != null)
                        {
                            Type t = f != null ? f.FieldType : p.PropertyType;
                            if (!(t.IsValueType || t == typeof(string)))
                            {
                                object value = f != null ? f.GetValue(element) : p.GetValue(element, null);
                                if (value != null)
                                {
                                    level++;
                                    WriteObject(m.Name + ": ", value);
                                    level--;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private void WriteValue(object o)
    {
        if (o == null)
        {
            Write("null");
        }
        else if (o is DateTime)
        {
            Write(((DateTime)o).ToShortDateString());
        }
        else if (o is ValueType || o is string)
        {
            Write(o.ToString());
        }
        else if (o is IEnumerable)
        {
            Write("...");
        }
        else
        {
            Write("{ }");
        }
    }
}